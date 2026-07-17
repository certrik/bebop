import unittest
from unittest.mock import patch, MagicMock
from app.headers import main

class TestHeaders(unittest.TestCase):
    def setUp(self):
        self.mock_request = MagicMock()
        self.mock_request.headers = {
            'etag': 'test-etag',
            'server': 'test-server'
        }

    @patch('app.headers.query_modat')
    @patch('app.headers.query_shodan')
    @patch('app.headers.query_censys')
    @patch('app.headers.query_zoomeye')
    @patch('app.headers.query_fofa')
    def test_headers_processing(self, mock_query_fofa, mock_query_zoomeye, mock_query_censys,
                                mock_query_shodan, mock_query_modat):
        findings = main(self.mock_request, doshodan=True, docensys=True, dozoome=True, dofofa=True)

        self.assertEqual(findings['interesting_headers'], ['etag', 'server'])

        # etag pivots (multiple engines are queried, so use assert_any_call)
        mock_query_shodan.assert_any_call('http.headers.etag:"test-etag"')
        mock_query_censys.assert_any_call('web.endpoints.http.headers: (key="etag" and value="test-etag")')
        mock_query_zoomeye.assert_any_call('header.etag:"test-etag"')
        mock_query_fofa.assert_any_call('header.etag="test-etag"')

        # server pivots
        mock_query_shodan.assert_any_call('http.headers.server:"test-server"')
        mock_query_censys.assert_any_call('web.endpoints.http.headers: (key="server" and value="test-server")')
        mock_query_zoomeye.assert_any_call('header.server:"test-server"')
        mock_query_fofa.assert_any_call('header.server="test-server"')

if __name__ == '__main__':
    unittest.main() 