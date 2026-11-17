"""Private, fixed-source subscription cache; listen inside 3x-ui's loopback only."""
import base64
import collections
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BYTES = 2 << 20
CHAIN_SUBSCRIPTION_PREFIX = '/subscription/'
SCHEMES = {'anytls', 'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2',
           'hy2', 'hysteria', 'tuic', 'wireguard', 'socks', 'socks5'}

def validate_https_target(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('invalid HTTPS target')
    try:
        addresses = {ipaddress.ip_address(parsed.hostname)}
    except ValueError:
        addresses = {ipaddress.ip_address(item[4][0]) for item in
                     socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError('non-public HTTPS target')

class HTTPSRedirectOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        validate_https_target(newurl)
        return super().redirect_request(request, fp, code, message, headers, newurl)

def decode_links(body):
    if len(body) > MAX_BYTES:
        raise ValueError('body limit')
    text = body.decode('utf-8-sig').strip()
    if '://' not in text:
        clean = ''.join(text.split())
        text = base64.b64decode(clean + '=' * (-len(clean) % 4),
                                altchars=b'-_', validate=True).decode('utf-8-sig')
    links = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        scheme = line.split('://', 1)[0].lower()
        if scheme not in SCHEMES or '://' not in line:
            raise ValueError('unsupported subscription line')
        if line not in links:
            links.append(line)
    if not links:
        raise ValueError('empty subscription')
    return links

class Cache:
    def __init__(self, config, root):
        self.config, self.root = config, Path(root)
        self.lock = threading.Lock()
        self.items, self.failures = {}, {}
        names = [source['name'] for source in config['sources']]
        if len(set(names)) != len(names) or not all(re.fullmatch(r'[A-Za-z0-9_-]{1,32}', n) for n in names):
            raise ValueError('invalid source names')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for source in config['sources']:
            if urllib.parse.urlsplit(source['url']).scheme != 'https':
                raise ValueError('upstream requires HTTPS')
            try:
                entry = json.loads((self.root / (source['name'] + '.json')).read_text())
                decode_links('\n'.join(entry['links']).encode())
                self.items[source['name']] = entry
            except (OSError, ValueError, KeyError):
                pass

    def refresh(self):
        for source in self.config['sources']:
            name = source['name']
            try:
                request = urllib.request.Request(source['url'], headers={
                    'User-Agent': 'v2rayNG/1.9', 'Accept': 'text/plain'})
                # Certificate verification remains enabled, including redirects.
                opener = urllib.request.build_opener(HTTPSRedirectOnly())
                with opener.open(request, timeout=25) as response:
                    if urllib.parse.urlsplit(response.url).scheme != 'https':
                        raise ValueError('insecure redirect')
                    links = decode_links(response.read(MAX_BYTES + 1))
                entry = {'links': links, 'fetched_at': time.time()}
                temp = self.root / (name + '.tmp')
                with temp.open('w', encoding='utf-8') as file:
                    os.chmod(temp, 0o600)
                    json.dump(entry, file)
                temp.replace(self.root / (name + '.json'))
                with self.lock:
                    self.items[name] = entry
                    self.failures.pop(name, None)
                counts = dict(collections.Counter(x.split('://')[0] for x in links))
                print(json.dumps({'event': 'refresh_ok', 'count': len(links),
                                  'protocols': counts}), flush=True)
            except Exception as error:
                # Never log exception text: URLs and upstream bodies can contain secrets.
                with self.lock:
                    self.failures[name] = type(error).__name__
                print(json.dumps({'event': 'refresh_failed',
                                  'error_type': type(error).__name__}), flush=True)

    def snapshot(self):
        with self.lock:
            now, links, details = time.time(), [], []
            for source in self.config['sources']:
                name = source['name']
                entry = self.items.get(name)
                age = now - entry['fetched_at'] if entry else None
                usable = entry is not None and 0 <= age <= self.config['max_stale_seconds']
                details.append({'name': name, 'usable': usable,
                                'age_seconds': int(age) if age is not None else None,
                                'last_error': self.failures.get(name)})
                if usable:
                    links.extend(x for x in entry['links'] if x not in links)
            return links, details

    def loop(self):
        while True:
            self.refresh()
            time.sleep(max(30, self.config['refresh_seconds']))

def make_handler(cache):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path == '/health':
                route, source_url = 'health', None
            elif self.path == '/subscription':
                route, source_url = 'subscription', None
            elif self.path.startswith(CHAIN_SUBSCRIPTION_PREFIX):
                # The upstream URL is the raw suffix. Its query string (for
                # example ?token=...) belongs to that URL and must be kept.
                route = 'subscription'
                source_url = self.path[len(CHAIN_SUBSCRIPTION_PREFIX):]
            else:
                self.reply(404, b'not found\n')
                return
            if 'chain' in cache.config:
                prepared, status = cache.snapshot(source_url)
                if route == 'health':
                    self.reply(200 if status['ready'] else 503,
                               json.dumps(status, ensure_ascii=False).encode(), 'application/json')
                elif prepared:
                    try:
                        body = cache.document(prepared)
                    except Exception:
                        self.reply(503, b'configuration unavailable\n')
                        return
                    self.reply(200, body, 'application/yaml; charset=utf-8')
                else:
                    self.reply(503, b'no usable chain cache\n')
                return
            links, details = cache.snapshot()
            if self.path == '/health':
                body = json.dumps({'ready': bool(links), 'nodes': len(links),
                                   'sources': details}).encode()
                self.reply(200 if links else 503, body, 'application/json')
            elif links:
                self.reply(200, base64.b64encode(('\n'.join(links)+'\n').encode()))
            else:
                self.reply(503, b'no usable cache\n')

        def reply(self, status, body, kind='text/plain; charset=utf-8'):
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
    return Handler

def main():
    os.umask(0o077)
    config = json.loads(Path('/config/config.json').read_text())
    if 'chain' in config:
        from chain import ChainCache
        cache = ChainCache(config, '/cache', HTTPSRedirectOnly)
    else:
        cache = Cache(config, '/cache')
    threading.Thread(target=cache.loop, daemon=True).start()
    server = ThreadingHTTPServer(('127.0.0.1', 18082), make_handler(cache))
    server.daemon_threads = True
    server.serve_forever()

if __name__ == '__main__':
    main()

