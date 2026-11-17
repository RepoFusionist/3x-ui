"""Generate a Mihomo chain without exposing the upstream subscription URL."""
import copy
import hashlib
import ipaddress
import json
import os
import socket
import threading
import time
import traceback
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

MAX_BYTES = 2 << 20
ENTRY_PROVIDER = '101中转节点'
EXIT_PROVIDER = '101出口节点'
AUTO_GROUP = '101自动'
EXIT_NAME = '备用线路-美国'
PREFIX = '101入口 · '


def validate_subscription_url(source_url):
    parsed = urllib.parse.urlsplit(source_url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('invalid upstream URL')
    try:
        addresses = {ipaddress.ip_address(parsed.hostname)}
    except ValueError:
        addresses = {ipaddress.ip_address(item[4][0]) for item in
                     socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError('non-public upstream address')


def prepare_upstream(document, automatic_name='自动选择'):
    """Keep the provider's automatic group and only its concrete dependencies."""
    if not isinstance(document, dict):
        raise ValueError('expected Clash mapping')
    groups = document.get('proxy-groups', [])
    automatic = next((g for g in groups if g.get('name') == automatic_name), None)
    if not automatic or automatic.get('type') != 'url-test':
        raise ValueError('automatic group missing')
    by_name = {}
    for proxy in document.get('proxies', []):
        if not isinstance(proxy, dict) or not isinstance(proxy.get('name'), str):
            raise ValueError('invalid proxy')
        if proxy['name'] in by_name:
            raise ValueError('duplicate proxy')
        by_name[proxy['name']] = proxy
    selected = automatic.get('proxies')
    if not isinstance(selected, list) or not selected or len(selected) > 512:
        raise ValueError('invalid automatic members')
    proxies = []
    for name in dict.fromkeys(selected):
        if name not in by_name:
            raise ValueError('automatic member is not a concrete proxy')
        proxy = copy.deepcopy(by_name[name])
        if any(key in proxy for key in ('dialer-proxy', 'interface-name', 'routing-mark')):
            raise ValueError('unexpected upstream dialer')
        if not proxy.get('type') or not proxy.get('server') or not proxy.get('port'):
            raise ValueError('incomplete proxy')
        proxy['name'] = PREFIX + name
        proxies.append(proxy)
    group = {key: copy.deepcopy(automatic[key]) for key in
             ('url', 'interval', 'tolerance', 'timeout', 'lazy', 'expected-status')
             if key in automatic}
    group.update(name=AUTO_GROUP, type='url-test', hidden=False, use=[ENTRY_PROVIDER])
    group.setdefault('url', 'https://www.gstatic.com/generate_204')
    group.setdefault('interval', 300)
    return {'proxies': proxies, 'group': group}


def exit_proxy(config):
    # These fields are deliberately explicit; SOCKS and cleartext HTTP are refused.
    if config.get('scheme') != 'https' or not config.get('username') or not config.get('password'):
        raise ValueError('authenticated HTTPS exit required')
    server, port = config['server'], int(config['port'])
    if not isinstance(server, str) or not server or not 1 <= port <= 65535:
        raise ValueError('invalid HTTPS exit')
    return {'name': EXIT_NAME, 'type': 'http', 'server': server, 'port': port,
            'username': config['username'], 'password': config['password'],
            'tls': True, 'sni': server, 'skip-cert-verify': False,
            'dialer-proxy': AUTO_GROUP, 'udp': False}


def generate(prepared, exit_config, template=None):
    """Inline providers avoid overwriting the native 3x-ui proxies array."""
    result = copy.deepcopy(template) if template is not None else {
        'mode': 'rule',
        'proxy-groups': [{'name': '专线', 'type': 'select', 'use': [EXIT_PROVIDER]}],
        'rules': ['MATCH,专线']}
    if not isinstance(result, dict) or 'proxies' in result:
        raise ValueError('rules must not replace native proxies')
    groups = result.setdefault('proxy-groups', [])
    if any(g.get('name') == AUTO_GROUP for g in groups):
        raise ValueError('automatic group collision')
    special = next((g for g in groups if g.get('name') == '专线'), None)
    if special is None or special.get('type') != 'select':
        raise ValueError('special selection group missing')
    special['use'] = list(dict.fromkeys(special.get('use', []) + [EXIT_PROVIDER]))
    if 'filter' in special:
        special['filter'] = '(' + special['filter'] + ')|^备用线路-美国$'
    providers = result.setdefault('proxy-providers', {})
    if ENTRY_PROVIDER in providers or EXIT_PROVIDER in providers:
        raise ValueError('provider collision')
    providers[ENTRY_PROVIDER] = {'type': 'inline', 'payload': copy.deepcopy(prepared['proxies'])}
    providers[EXIT_PROVIDER] = {'type': 'inline', 'payload': [exit_proxy(exit_config)]}
    groups.append(copy.deepcopy(prepared['group']))
    return result


class ChainCache:
    def __init__(self, config, root, redirect_handler):
        self.config, self.root = config, Path(root)
        self.lock = threading.Lock()
        self.refresh_lock = threading.Lock()
        self.entries, self.failures = {}, {}
        self.redirect_handler = redirect_handler
        if len(config['sources']) != 1:
            raise ValueError('chain requires one upstream')
        self.default_source_url = config['sources'][0]['url']
        validate_subscription_url(self.default_source_url)
        exit_proxy(config['chain']['exit'])
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._load_entry(self.default_source_url, self.root / 'chain.json')

    def _cache_path(self, source_url, suffix='.json'):
        digest = hashlib.sha256(source_url.encode('utf-8')).hexdigest()
        return self.root / ('chain-' + digest + suffix)

    def _load_entry(self, source_url, path=None):
        try:
            entry = json.loads((path or self._cache_path(source_url)).read_text())
            generate(entry['prepared'], self.config['chain']['exit'])
            with self.lock:
                self.entries[source_url] = entry
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def refresh(self, source_url=None):
        source_url = source_url or self.default_source_url
        validate_subscription_url(source_url)
        key = (self.root / 'chain.json' if source_url == self.default_source_url
               else self._cache_path(source_url))
        with self.refresh_lock:
            with self.lock:
                current = self.entries.get(source_url)
                if current and time.time() - current['fetched_at'] < self.config['refresh_seconds']:
                    return
            self._refresh_source(source_url, key)

    def _refresh_source(self, source_url, cache_path):
        try:
            request = urllib.request.Request(source_url, headers={
                'User-Agent': 'clash.meta', 'Accept': 'application/yaml'})
            opener = urllib.request.build_opener(self.redirect_handler())
            with opener.open(request, timeout=25) as response:
                if urllib.parse.urlsplit(response.url).scheme != 'https':
                    raise ValueError('insecure redirect')
                body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ValueError('upstream body limit')
            prepared = prepare_upstream(yaml.safe_load(body),
                                        self.config['chain'].get('automatic_group', '自动选择'))
            generate(prepared, self.config['chain']['exit'])
            entry = {'prepared': prepared, 'fetched_at': time.time()}
            temp = cache_path.with_suffix('.tmp')
            with temp.open('w', encoding='utf-8') as stream:
                os.chmod(temp, 0o600)
                json.dump(entry, stream, ensure_ascii=False)
            temp.replace(cache_path)
            with self.lock:
                self.entries[source_url] = entry
                self.failures.pop(source_url, None)
            print(json.dumps({'event': 'chain_refresh_ok',
                              'upstream_nodes': len(prepared['proxies']), 'exit_nodes': 1}), flush=True)
        except Exception as error:
            with self.lock:
                self.failures[source_url] = type(error).__name__
            print(json.dumps({'event': 'chain_refresh_failed',
                              'error_type': type(error).__name__,
                              'error_location': [
                                  [Path(frame.filename).name, frame.lineno]
                                  for frame in traceback.extract_tb(error.__traceback__)]}), flush=True)

    def snapshot(self, source_url=None):
        source_url = source_url or self.default_source_url
        validate_subscription_url(source_url)
        if source_url not in self.entries:
            self._load_entry(source_url)
        self.refresh(source_url)
        with self.lock:
            entry = self.entries.get(source_url)
            age = time.time() - entry['fetched_at'] if entry else None
            ready = age is not None and 0 <= age <= self.config['max_stale_seconds']
            prepared = copy.deepcopy(entry['prepared']) if ready else None
            status = {'ready': ready, 'format': 'mihomo', 'exit_name': EXIT_NAME,
                      'exit_nodes': 1 if ready else 0,
                      'upstream_nodes': len(prepared['proxies']) if ready else 0,
                      'age_seconds': int(age) if age is not None else None,
                      'last_error': self.failures.get(source_url)}
            return prepared, status

    def document(self, prepared):
        return yaml.safe_dump(generate(prepared, self.config['chain']['exit']),
                              allow_unicode=True, sort_keys=False).encode('utf-8')

    def loop(self):
        while True:
            self.refresh()
            time.sleep(max(30, self.config['refresh_seconds']))

