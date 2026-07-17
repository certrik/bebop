#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the out-of-band callback deanonymisation module (offline)."""
import types
import unittest
from unittest import mock

from app import oob


def _args(**kw):
    defaults = dict(oob_callback=None, oob_poll_url=None, oob_scheme=None,
                    oob_inject=None, oob_wait=None, oob_path_style=None)
    defaults.update(kw)
    return types.SimpleNamespace(**defaults)


class TestConfigResolution(unittest.TestCase):
    def test_disabled_without_host(self):
        self.assertIsNone(oob.resolve_config(_args(), env={}))

    def test_args_take_precedence(self):
        cfg = oob.resolve_config(
            _args(oob_callback='oob.example.net', oob_scheme='https',
                  oob_poll_url='https://api/poll?t={TOKEN}', oob_wait='40'),
            env={})
        self.assertEqual(cfg['host'], 'oob.example.net')
        self.assertEqual(cfg['scheme'], 'https')
        self.assertEqual(cfg['wait'], 40)

    def test_env_fallback_for_ci(self):
        env = {'BEBOP_OOB_CALLBACK': 'listen.example.net',
               'BEBOP_OOB_POLL_URL': 'https://api/poll?t={TOKEN}',
               'BEBOP_OOB_INJECT': 'https://t/?url={CALLBACK}'}
        cfg = oob.resolve_config(_args(), env=env)
        self.assertEqual(cfg['host'], 'listen.example.net')
        self.assertEqual(cfg['inject'], ['https://t/?url={CALLBACK}'])

    def test_path_style_env_truthiness(self):
        # non-empty env strings must not all read as True (plain bool() trap)
        for val, expect in [('1', True), ('true', True), ('YES', True),
                            ('on', True), ('0', False), ('false', False), ('', False)]:
            env = {'BEBOP_OOB_CALLBACK': 'h', 'BEBOP_OOB_PATH_STYLE': val}
            self.assertEqual(oob.resolve_config(_args(), env=env)['path_style'], expect,
                             f'BEBOP_OOB_PATH_STYLE={val!r}')
        # CLI bool still works
        self.assertTrue(oob.resolve_config(_args(oob_callback='h', oob_path_style=True), env={})['path_style'])


class TestCallbackUrl(unittest.TestCase):
    def test_subdomain_style_default(self):
        cfg = {'host': 'oob.example.net', 'scheme': 'http', 'path_style': False}
        url = oob._callback_url(cfg, 'tok123')
        self.assertEqual(url, 'http://tok123.oob.example.net')

    def test_path_style(self):
        cfg = {'host': 'oob.example.net', 'scheme': 'http', 'path_style': True}
        self.assertEqual(oob._callback_url(cfg, 'tok123'),
                         'http://oob.example.net/tok123')


class TestPingbackTrigger(unittest.TestCase):
    def test_pingback_body_and_route(self):
        captured = {}

        def fake_post(url, data=None, proxies=None, verify=None, timeout=None, headers=None):
            captured['url'] = url
            captured['data'] = data
            captured['proxies'] = proxies
            return types.SimpleNamespace(status_code=200, text='ok')

        with mock.patch.object(oob.requests, 'post', fake_post), \
             mock.patch.object(oob, 'getsocks', lambda: {'http': 'socks5h://127.0.0.1:9050'}):
            out = oob.trigger_pingback('http://abc.onion', 'http://tok.oob.example.net', usetor=True)

        self.assertTrue(captured['url'].endswith('/xmlrpc.php'))
        self.assertIn('pingback.ping', captured['data'])
        self.assertIn('http://tok.oob.example.net', captured['data'])   # sourceURI = callback
        self.assertIn('http://abc.onion', captured['data'])              # targetURI = onion
        self.assertIsNotNone(captured['proxies'])                        # routed over Tor
        self.assertEqual(out['status'], 200)


class TestPollParsing(unittest.TestCase):
    def _cfg(self):
        return {'host': 'x', 'scheme': 'http', 'poll_url': 'https://api/poll?t={TOKEN}',
                'inject': [], 'wait': 0, 'path_style': False}

    def test_extracts_source_ip_from_listener_json(self):
        payload = [{'protocol': 'http', 'remote-address': '203.0.113.9',
                    'timestamp': 't'}]

        def fake_get(url, proxies=None, verify=None, timeout=None, headers=None):
            self.assertIn('tok999', url)   # token substituted into poll url
            return types.SimpleNamespace(status_code=200, text='x', json=lambda: payload)

        with mock.patch.object(oob.requests, 'get', fake_get):
            res = oob.poll(self._cfg(), {'token': 'tok999'}, attempts=1)
        self.assertEqual(res['source_ips'], ['203.0.113.9'])

    def test_nested_and_hostport_forms(self):
        payload = {'data': {'items': [{'source_ip': '198.51.100.4:5555'}]}}

        def fake_get(url, proxies=None, verify=None, timeout=None, headers=None):
            return types.SimpleNamespace(status_code=200, text='x', json=lambda: payload)

        with mock.patch.object(oob.requests, 'get', fake_get):
            res = oob.poll(self._cfg(), {'token': 't'}, attempts=1)
        self.assertEqual(res['source_ips'], ['198.51.100.4'])

    def test_no_poll_url_returns_empty(self):
        cfg = self._cfg(); cfg['poll_url'] = None
        res = oob.poll(cfg, {'token': 't'}, attempts=1)
        self.assertEqual(res['source_ips'], [])


if __name__ == '__main__':
    unittest.main()
