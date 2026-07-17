#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the findings-only text/Markdown report."""
import unittest

from app.textreport import generate_text_report


FULL = {
    'target': 'http://abc.onion',
    'duration': '1m 2s',
    'summary': {'fqdn': 'abc.onion', 'use_tor': True},
    'deanon_candidates': [{
        'candidate': '45.33.32.156', 'categories': ['jarm', 'favicon'],
        'sources': ['shodan'], 'confirmation': {
            'verdict': 'CONFIRMED', 'matches': ['body_sha256'],
            'url': 'https://45.33.32.156/'}}],
    'origin_leaks': [{'candidate': '203.0.113.9', 'verdict': 'LIKELY',
                      'matches': ['title', 'server'], 'url': 'http://203.0.113.9/'}],
    'oob': {'source_ips': ['198.51.100.4'], 'confirmations': []},
    'ports': {'ports': [{'port': '22', 'name': 'ssh', 'product': 'OpenSSH',
                         'version': '8.9', 'banner': 'SSH-2.0'}]},
    'discovered_paths': [{'method': 'GET', 'path': '/.ssh/config', 'status_code': 200,
                          'description': 'SSH client config', 'matched_text': None,
                          'indicators': {'public_ips': [], 'private_ips': ['10.0.0.9'],
                                         'hostnames': ['db.internal']}}],
    'certificate': {'common_name': 'origin.example', 'issuer': 'CA', 'serial': 1},
    'tls_fingerprint': {'jarm': '27d40d', 'cert_fingerprints': {'sha256': 'abcd'}},
    'favicon': {'mmh3': -1, 'md5': 'ff', 'location': '/favicon.ico'},
    'headers': {'interesting_headers': ['server'], 'security_headers': {}},
    'all_headers': {'Server': 'nginx', 'X-Powered-By': 'PHP/8.1'},
    'title': 'Panel',
    'contentleak': {'body_hash': {'sha256': 'cc'}, 'emails': ['a@b.com']},
    'analytics': {'google_analytics': ['UA-1']},
    'cryptocurrency': {'btc': ['1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'], 'eth': [], 'xmr': []},
    'robotsmap': {'robots_txt': {'disallowed_paths': [{'path': '/admin'}]}, 'sitemaps': []},
    'pagespider': {'samedomain': ['http://abc.onion/a'], 'extdomain': [], 'emails': []},
    'domains': ['known.example'],
    'reverse_resolved': {'45.33.32.156': ['origin.example']},
}


class TestTextReport(unittest.TestCase):
    def test_contains_all_finding_types(self):
        r = generate_text_report(FULL)
        for needle in ['# bebop findings', '45.33.32.156', 'CONFIRMED',
                       '203.0.113.9', '198.51.100.4', 'OpenSSH', '/.ssh/config',
                       'db.internal', 'origin.example', 'JARM', 'Panel',
                       'UA-1', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
                       '/admin', 'X-Powered-By', 'known.example']:
            self.assertIn(needle, r, needle)

    def test_no_error_or_log_noise(self):
        # findings-only: no error/traceback/log-level words
        r = generate_text_report(FULL).lower()
        for banned in ['error', 'traceback', 'exception', 'warning', 'debug:']:
            self.assertNotIn(banned, r, banned)

    def test_empty_sections_omitted(self):
        r = generate_text_report({'target': 'http://x.onion',
                                  'summary': {'use_tor': True}})
        # only the header block, no finding sections
        self.assertIn('# bebop findings', r)
        self.assertNotIn('## Open ports', r)
        self.assertNotIn('## Deanonymisation candidates', r)

    def test_returns_string_ending_newline(self):
        r = generate_text_report(FULL)
        self.assertIsInstance(r, str)
        self.assertTrue(r.endswith('\n'))


if __name__ == '__main__':
    unittest.main()
