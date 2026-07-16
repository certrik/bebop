import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import json
import requests

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import subprocessors

class TestSubprocessors(unittest.TestCase):
    def setUp(self):
        # Mock environment variables
        self.env_patcher = patch.dict('os.environ', {
            'FOFA_API_KEY': 'test_fofa_key',
            'FOFA_API_MAIL': 'test@example.com',
            'CENSYS_API_ID': 'test_censys_id',
            'CENSYS_API_SECRET': 'test_censys_secret',
            'SHODAN_API_KEY': 'test_shodan_key',
            'ZOOMEYE_API_KEY': 'test_zoomeye_key',
            'MODAT_API_KEY': 'test_modat_key',
            'URLSCAN_API_KEY': 'test_urlscan_key',
            'VIRUSTOTAL_API_KEY': 'test_virustotal_key',
            'SECURITYTRAILS_API_KEY': 'test_securitytrails_key'
        })
        self.env_patcher.start()

    def tearDown(self):
        self.env_patcher.stop()

    @patch('app.subprocessors.ZOOMEYE_API_KEY', 'test_zoomeye_key')
    @patch('requests.post')
    def test_query_zoomeye(self, mock_post):
        # Test successful query (ZoomEye v2 /v2/search response shape)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'code': 60000,
            'total': 2,
            'data': [
                {'ip': '1.1.1.1', 'port': 80, 'banner': 'test banner 1'},
                {'ip': '2.2.2.2', 'port': 443, 'banner': 'test banner 2'}
            ]
        }
        mock_post.return_value = mock_response

        results = subprocessors.query_zoomeye('test query')
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['ip'], '1.1.1.1')

        # Test query with too many results
        mock_response.json.return_value = {'code': 60000, 'total': 21, 'data': []}
        results = subprocessors.query_zoomeye('test query')
        self.assertEqual(len(results), 0)

        # Test API-level error code
        mock_response.json.return_value = {'code': 60001, 'message': 'auth failed'}
        results = subprocessors.query_zoomeye('test query')
        self.assertEqual(len(results), 0)

        # Test HTTP error
        mock_post.side_effect = requests.exceptions.HTTPError()
        results = subprocessors.query_zoomeye('test query')
        self.assertEqual(len(results), 0)

    @patch('app.subprocessors.MODAT_API_KEY', 'test_modat_key')
    @patch('requests.post')
    def test_query_modat(self, mock_post):
        # Test successful query (Modat service-search response shape)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'total_records': 2,
            'page': [
                {'ip': '1.1.1.1', 'service': {'port': 443}},
                {'ip': '2.2.2.2', 'service': {'port': 80}},
            ]
        }
        mock_post.return_value = mock_response

        results = subprocessors.query_modat('web.title ~ "Login"')
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['ip'], '1.1.1.1')
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], 'https://api.magnify.modat.io/service/search/v1')
        self.assertEqual(kwargs['json']['query'], 'web.title ~ "Login"')
        self.assertEqual(kwargs['headers']['Authorization'], 'Bearer test_modat_key')

        # Test query with too many results
        mock_response.json.return_value = {'total_records': 21, 'page': []}
        results = subprocessors.query_modat('web.title ~ "Login"')
        self.assertEqual(len(results), 0)

        # Test HTTP error
        mock_post.side_effect = requests.exceptions.HTTPError()
        results = subprocessors.query_modat('web.title ~ "Login"')
        self.assertEqual(len(results), 0)

    @patch('app.subprocessors.SDK')
    @patch('app.subprocessors.CENSYS_ORGANIZATION_ID', 'test_org')
    @patch('app.subprocessors.CENSYS_PERSONAL_ACCESS_TOKEN', 'test_token')
    def test_query_censys(self, mock_sdk_cls):
        # SDK() is used as a context manager returning the client instance
        sdk_instance = MagicMock()
        mock_sdk_cls.return_value.__enter__.return_value = sdk_instance

        def make_response(hits):
            # Envelope shape: response.result.result.hits
            resp = MagicMock()
            resp.result.result.hits = hits
            return resp

        # Test successful query (Censys Platform response shape)
        sdk_instance.global_data.search.return_value = make_response(
            [{'ip': '1.1.1.1'}, {'ip': '2.2.2.2'}])
        results = subprocessors.query_censys('host.dns.names="example.com"')
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['ip'], '1.1.1.1')

        # Test query with too many results
        sdk_instance.global_data.search.return_value = make_response(
            [{'ip': f'{i}.{i}.{i}.{i}'} for i in range(21)])
        results = subprocessors.query_censys('host.dns.names="example.com"')
        self.assertEqual(len(results), 0)

        # Test Censys API error
        sdk_instance.global_data.search.side_effect = Exception('boom')
        results = subprocessors.query_censys('host.dns.names="example.com"')
        self.assertEqual(len(results), 0)

    @patch('requests.get')
    def test_query_fofa(self, mock_get):
        # Test successful query
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'size': 2,
            'results': [
                ['1.1.1.1', 'test.com'],
                ['2.2.2.2', 'example.com']
            ]
        }
        mock_get.return_value = mock_response

        results = subprocessors.query_fofa('test query')
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['ip'], '1.1.1.1')

        # Test query with too many results
        mock_response.json.return_value = {'size': 21, 'results': []}
        results = subprocessors.query_fofa('test query')
        self.assertEqual(len(results), 0)

        # Test HTTP error
        mock_get.side_effect = requests.exceptions.RequestException()
        results = subprocessors.query_fofa('test query')
        self.assertEqual(len(results), 0)

    @patch('requests.get')
    def test_query_resolutions_securitytrails(self, mock_get):
        # Test successful query
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'records': [
                {'hostname': 'test.com'},
                {'hostname': 'example.com'}
            ]
        }
        mock_get.return_value = mock_response

        results = subprocessors.query_resolutions_securitytrails('1.1.1.1')
        self.assertEqual(len(results), 2)
        self.assertIn('test.com', results)

        # Test HTTP error
        mock_get.side_effect = requests.exceptions.RequestException()
        results = subprocessors.query_resolutions_securitytrails('1.1.1.1')
        self.assertEqual(len(results), 0)

    @patch('requests.get')
    def test_query_resolutions_virustotal(self, mock_get):
        # Test successful query
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'attributes': {
                    'resolutions': [
                        {'hostname': 'test.com'},
                        {'hostname': 'example.com'}
                    ]
                }
            }
        }
        mock_get.return_value = mock_response

        results = subprocessors.query_resolutions_virustotal('1.1.1.1')
        self.assertEqual(len(results), 2)
        self.assertIn('test.com', results)

        # Test HTTP error
        mock_get.side_effect = requests.exceptions.RequestException()
        results = subprocessors.query_resolutions_virustotal('1.1.1.1')
        self.assertEqual(len(results), 0)

    @patch('requests.get')
    def test_query_resolutions_urlscan(self, mock_get):
        # Test successful query
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'results': [
                {'page': {'domain': 'test.com'}},
                {'page': {'domain': 'example.com'}}
            ]
        }
        mock_get.return_value = mock_response

        results = subprocessors.query_resolutions_urlscan('1.1.1.1')
        self.assertEqual(len(results), 2)
        self.assertIn('test.com', results)

        # Test HTTP error
        mock_get.side_effect = requests.exceptions.RequestException()
        results = subprocessors.query_resolutions_urlscan('1.1.1.1')
        self.assertEqual(len(results), 0)

if __name__ == '__main__':
    unittest.main() 