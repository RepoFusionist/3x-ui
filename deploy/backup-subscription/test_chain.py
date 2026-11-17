import base64
import unittest

import chain


class SubscriptionInformationTests(unittest.TestCase):
    def test_mihomo_excludes_information_nodes(self):
        doc = {
            'proxies': [
                {'name': '剩余流量 64 GB', 'type': 'trojan', 'server': 'info.example', 'port': 443},
                {'name': '真实节点', 'type': 'trojan', 'server': 'node.example', 'port': 443},
            ],
            'proxy-groups': [{'name': '自动选择', 'type': 'url-test',
                              'proxies': ['剩余流量 64 GB', '真实节点']}],
        }
        result = chain.prepare_upstream(doc)
        self.assertEqual([p['name'] for p in result['proxies']], ['101入口 · 真实节点'])
        self.assertIs(result['group']['lazy'], False)

    def test_base64_share_links_exclude_information(self):
        body = ('trojan://pass@info.example:443#剩余流量%2064GB\n'
                'trojan://pass@node.example:443#node\n').encode()
        result = chain.prepare_share_subscription(base64.b64encode(body))
        self.assertEqual(len(result['proxies']), 1)
        self.assertIn('node.example', result['proxies'][0]['link'])


if __name__ == '__main__':
    unittest.main()

