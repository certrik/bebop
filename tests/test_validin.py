import unittest
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import subprocessors


class TestValidin(unittest.TestCase):
    def _resp(self, payload, status=200):
        r = MagicMock()
        r.status_code = status
        r.json.return_value = payload
        r.raise_for_status.return_value = None
        return r

    # --- reverse passive-DNS resolutions ---------------------------------
    @patch('app.subprocessors.VALIDIN_API_KEY', 'test_validin_key')
    @patch('app.subprocessors.requests.get')
    def test_resolutions_extracts_historical_hostnames(self, mock_get):
        mock_get.return_value = self._resp({
            'query_key': '1.2.3.4',
            'status': 'finished',
            'records': {
                'A': [
                    {'key': 'old-origin.example', 'value': '1.2.3.4',
                     'value_type': 'ip4', 'first_seen': 111, 'last_seen': 222},
                    {'key': 'also-here.example', 'value': '1.2.3.4',
                     'value_type': 'ip4', 'first_seen': 333, 'last_seen': 444},
                ],
                'PTR': [
                    {'key': '1.2.3.4', 'value': 'ptr-name.example',
                     'value_type': 'dom', 'first_seen': 1, 'last_seen': 2},
                ],
            },
        })
        out = subprocessors.query_resolutions_validin('1.2.3.4')
        self.assertEqual(out, {'old-origin.example', 'also-here.example', 'ptr-name.example'})
        # correct URL + BEARER auth header
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], 'https://app.validin.com/api/axon/ip/dns/history/1.2.3.4')
        self.assertEqual(kwargs['headers']['Authorization'], 'BEARER test_validin_key')

    @patch('app.subprocessors.VALIDIN_API_KEY', 'k')
    @patch('app.subprocessors.requests.get')
    def test_resolutions_excludes_the_ip_itself(self, mock_get):
        mock_get.return_value = self._resp({
            'records': {'A': [{'key': '9.9.9.9', 'value': '9.9.9.9', 'value_type': 'ip4'}]}
        })
        self.assertEqual(subprocessors.query_resolutions_validin('9.9.9.9'), set())

    @patch('app.subprocessors.VALIDIN_API_KEY', None)
    def test_resolutions_no_key_returns_empty(self):
        self.assertEqual(subprocessors.query_resolutions_validin('1.2.3.4'), set())

    # --- host-response hash pivots ---------------------------------------
    @patch('app.subprocessors.VALIDIN_API_KEY', 'test_validin_key')
    @patch('app.subprocessors.requests.get')
    def test_hash_pivot_hits_correct_endpoint(self, mock_get):
        mock_get.return_value = self._resp({
            'records': {
                'CRAWL': [
                    {'key': 'deadbeef', 'value': 'origin.example',
                     'value_type': 'dom', 'last_seen': 999},
                ]
            }
        })
        out = subprocessors.query_validin_pivot('deadbeef')
        self.assertEqual(len(out), 1)
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], 'https://app.validin.com/api/axon/hash/pivots/deadbeef')
        self.assertEqual(kwargs['headers']['Authorization'], 'BEARER test_validin_key')

    @patch('app.subprocessors.VALIDIN_API_KEY', None)
    def test_hash_pivot_no_key_returns_empty(self):
        self.assertEqual(subprocessors.query_validin_pivot('abc'), [])

    @patch('app.subprocessors.VALIDIN_API_KEY', 'k')
    @patch('app.subprocessors.requests.get')
    def test_api_error_returns_empty(self, mock_get):
        import requests as _rq
        mock_get.side_effect = _rq.exceptions.RequestException('boom')
        self.assertEqual(subprocessors.query_resolutions_validin('1.2.3.4'), set())
        self.assertEqual(subprocessors.query_validin_pivot('abc'), [])


if __name__ == '__main__':
    unittest.main()
