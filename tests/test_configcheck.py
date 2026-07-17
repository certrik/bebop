#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for config-check origin-indicator extraction and path integrity."""
import ast
import unittest

from app.configcheck import extract_origin_indicators, interesting_paths


class TestOriginIndicatorExtraction(unittest.TestCase):
    def test_phpinfo_server_addr(self):
        body = ('This program makes use of the Zend engine. '
                '_SERVER["SERVER_ADDR"] => 45.33.32.156')
        ind = extract_origin_indicators(body)
        self.assertIn('45.33.32.156', ind['public_ips'])

    def test_private_and_loopback_separated(self):
        ind = extract_origin_indicators('backend 10.0.0.5 and loopback 127.0.0.1')
        self.assertIn('10.0.0.5', ind['private_ips'])
        self.assertNotIn('127.0.0.1', ind['public_ips'] + ind['private_ips'])

    def test_documentation_range_not_public(self):
        # 203.0.113.0/24 is TEST-NET-3 - never a real origin.
        ind = extract_origin_indicators('SERVER_ADDR => 203.0.113.45')
        self.assertNotIn('203.0.113.45', ind['public_ips'])

    def test_prometheus_instance_label(self):
        body = 'http_requests_total{instance="8.8.4.4:9100",job="node"} 5'
        self.assertIn('8.8.4.4', extract_origin_indicators(body)['public_ips'])

    def test_hostname_from_connection_string(self):
        body = '{"value":"jdbc:mysql://db.internal.corp:3306/app"}'
        self.assertIn('db.internal.corp', extract_origin_indicators(body)['hostnames'])

    def test_cdn_noise_filtered(self):
        body = '<script src="https://cdnjs.cloudflare.com/x.js"></script>'
        self.assertNotIn('cdnjs.cloudflare.com',
                         extract_origin_indicators(body)['hostnames'])

    def test_onion_not_a_hostname(self):
        body = 'canonical https://abc123def456.onion/path'
        self.assertEqual(extract_origin_indicators(body)['hostnames'], [])

    def test_empty_body(self):
        self.assertEqual(
            extract_origin_indicators(''),
            {'public_ips': [], 'private_ips': [], 'hostnames': []})


class TestPathIntegrity(unittest.TestCase):
    def test_no_duplicate_uri_method(self):
        keys = [(p['uri'], p.get('method', 'GET')) for p in interesting_paths]
        self.assertEqual(len(keys), len(set(keys)), 'duplicate (uri, method) entries')

    def test_every_entry_well_formed(self):
        for p in interesting_paths:
            self.assertIn('uri', p)
            self.assertIn('code', p)
            self.assertIn('text', p)
            self.assertIn('desc', p)

    def test_post_checks_carry_a_body(self):
        for p in interesting_paths:
            if p.get('method') == 'POST':
                self.assertTrue(p.get('json') is not None or p.get('data') is not None,
                                f'{p["uri"]} POST check has no body')


if __name__ == '__main__':
    unittest.main()
