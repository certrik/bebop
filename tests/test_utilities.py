import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import socket
import shutil

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import utilities

class TestUtilities(unittest.TestCase):
    def setUp(self):
        self.env_patcher = patch.dict('os.environ', {
            'SOCKS_PORT': '9050',
            'SOCKS_HOST': '127.0.0.1'
        })
        self.env_patcher.start()

    def tearDown(self):
        self.env_patcher.stop()

    @patch('socket.gethostbyname')
    def test_nsresolve(self, mock_gethostbyname):
        # Test successful resolution
        mock_gethostbyname.return_value = '1.1.1.1'
        result = utilities.nsresolve('example.com')
        self.assertEqual(result, '1.1.1.1')
        mock_gethostbyname.assert_called_with('example.com')

        # Test failed resolution
        mock_gethostbyname.side_effect = socket.gaierror()
        result = utilities.nsresolve('nonexistent.com')
        self.assertIsNone(result)

    def test_validurl(self):
        # Test valid URLs
        valid_urls = [
            'http://example.com',
            'https://example.com',
            'http://sub.example.com',
            'https://example.com:8080',
            'http://192.168.1.1',
            'https://192.168.1.1:8080'
        ]
        for url in valid_urls:
            self.assertTrue(utilities.validurl(url), f"URL should be valid: {url}")

        # Test invalid URLs
        invalid_urls = [
            'not_a_url',
            'ftp://example.com',
            'http:/example.com',
            'http://example',
            '192.168.1',
            'https://'
        ]
        for url in invalid_urls:
            self.assertFalse(utilities.validurl(url), f"URL should be invalid: {url}")

    @patch('app.utilities.nsresolve')
    def test_getproxyvalue(self, mock_nsresolve):
        # Test with docker.internal
        mock_nsresolve.return_value = '172.17.0.1'
        addr, port = utilities.getproxyvalue()
        self.assertEqual(addr, 'host.docker.internal')
        self.assertEqual(port, 9050)

        # Test without docker.internal
        mock_nsresolve.return_value = None
        addr, port = utilities.getproxyvalue()
        self.assertEqual(addr, '127.0.0.1')
        self.assertEqual(port, 9050)

    @patch('socket.socket')
    def test_checktcp(self, mock_socket):
        # Test successful connection
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock
        
        result = utilities.checktcp('127.0.0.1', 80)
        self.assertTrue(result)
        mock_sock.connect_ex.assert_called_with(('127.0.0.1', 80))

        # Test failed connection
        mock_sock.connect_ex.return_value = 1
        result = utilities.checktcp('127.0.0.1', 80)
        self.assertFalse(result)

        # Test resolution error
        mock_sock.connect_ex.side_effect = socket.gaierror()
        with self.assertRaises(SystemExit):
            utilities.checktcp('invalid.host', 80)

    def test_getfqdn(self):
        # Test with subdomain
        result = utilities.getfqdn('https://sub.example.com/path')
        self.assertEqual(result, 'sub.example.com')

        # Test without subdomain
        result = utilities.getfqdn('https://example.com/path')
        self.assertEqual(result, 'example.com')

        # Test with different TLD
        result = utilities.getfqdn('https://sub.example.co.uk/path')
        self.assertEqual(result, 'sub.example.co.uk')

    def test_getport(self):
        # Test URL with port
        result = utilities.getport('https://example.com:8080/path')
        self.assertEqual(result, 8080)

        # Test URL without port
        result = utilities.getport('https://example.com/path')
        self.assertIsNone(result)

    def test_getbaseurl(self):
        # Test URL with path
        result = utilities.getbaseurl('https://example.com/path/to/resource')
        self.assertEqual(result, 'https://example.com')

        # Test URL without path
        result = utilities.getbaseurl('https://example.com')
        self.assertEqual(result, 'https://example.com')

        # Test URL with port
        result = utilities.getbaseurl('https://example.com:8080/path')
        self.assertEqual(result, 'https://example.com:8080')

    def test_getsocks(self):
        # Test with aio_fmt=False
        result = utilities.getsocks(aio_fmt=False)
        expected = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        self.assertEqual(result, expected)

        # Test with aio_fmt=True
        result = utilities.getsocks(aio_fmt=True)
        expected = {
            'http': 'socks5://127.0.0.1:9050',
            'https': 'socks5://127.0.0.1:9050'
        }
        self.assertEqual(result, expected)

    @patch('shutil.which')
    @patch('os.path.isfile')
    def test_preflight(self, mock_isfile, mock_which):
        # Test successful preflight
        mock_which.return_value = '/usr/bin/proxychains4'
        mock_isfile.return_value = True
        
        utilities.preflight()  # Should not raise any exception
        
        # Test missing path item
        mock_which.return_value = None
        with self.assertRaises(SystemExit):
            utilities.preflight()
            
        # Test missing file
        mock_which.return_value = '/usr/bin/proxychains4'
        mock_isfile.return_value = False
        with self.assertRaises(SystemExit):
            utilities.preflight()

if __name__ == '__main__':
    unittest.main() 