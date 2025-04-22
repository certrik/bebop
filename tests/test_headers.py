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

    @patch('app.headers.query_shodan')
    @patch('app.headers.query_censys')
    @patch('app.headers.query_zoomeye')
    @patch('app.headers.query_fofa')
    def test_headers_processing(self, mock_query_fofa, mock_query_zoomeye, mock_query_censys, mock_query_shodan):
        interesting_headers = main(self.mock_request, doshodan=True, docensys=True, dozoome=True, dofofa=True)
        
        self.assertEqual(len(interesting_headers), 2)
        self.assertIn('etag', interesting_headers)
        self.assertIn('server', interesting_headers)
        
        mock_query_shodan.assert_called_with('http.headers.etag:"test-etag"')
        mock_query_censys.assert_called_with('services.http.response.headers.etag:"test-etag"')
        mock_query_zoomeye.assert_called_with('header.etag:"test-etag"')
        mock_query_fofa.assert_called_with('header.etag="test-etag"')
        
        mock_query_shodan.assert_called_with('http.headers.server:"test-server"')
        mock_query_censys.assert_called_with('services.http.response.headers.server:"test-server"')
        mock_query_zoomeye.assert_called_with('header.server:"test-server"')
        mock_query_fofa.assert_called_with('header.server="test-server"')

if __name__ == '__main__':
    unittest.main() 