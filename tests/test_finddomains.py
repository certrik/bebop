import unittest
from unittest.mock import patch, MagicMock
from app.finddomains import main, reverse_dns_lookup, check_hostname_resolvematch

class TestFindDomains(unittest.TestCase):
    @patch('app.finddomains.reverse_dns_lookup')
    @patch('app.finddomains.subprocessors.query_resolutions_virustotal')
    @patch('app.finddomains.subprocessors.query_resolutions_urlscan')
    @patch('app.finddomains.subprocessors.query_resolutions_securitytrails')
    @patch('app.finddomains.check_hostname_resolvematch')
    def test_main_function(self, mock_check_resolve, mock_securitytrails, mock_urlscan, mock_virustotal, mock_reverse_dns):
        # Setup mocks
        mock_reverse_dns.return_value = "example.com"
        mock_virustotal.return_value = {"domain1.com", "domain2.com"}
        mock_urlscan.return_value = {"domain2.com", "domain3.com"}
        mock_securitytrails.return_value = {"domain3.com", "domain4.com"}
        mock_check_resolve.return_value = ["domain1.com", "domain2.com"]
        
        # Call the function
        result = main("192.168.1.1")
        
        # Assertions
        mock_reverse_dns.assert_called_with("192.168.1.1")
        mock_virustotal.assert_called_with("192.168.1.1")
        mock_urlscan.assert_called_with("192.168.1.1")
        mock_securitytrails.assert_called_with("192.168.1.1")
        
        # Check that check_hostname_resolvematch was called with the combined hostnames
        expected_hostnames = {"domain1.com", "domain2.com", "domain3.com", "domain4.com", "example.com"}
        mock_check_resolve.assert_called_with(expected_hostnames, "192.168.1.1")
        
        # Check the result
        self.assertEqual(result, ["domain1.com", "domain2.com"])
    
    @patch('app.finddomains.get_proxy_socket')
    def test_reverse_dns_lookup(self, mock_get_proxy_socket):
        # Setup mock
        mock_socket = MagicMock()
        mock_socket.gethostbyaddr.return_value = ("example.com", [], [])
        mock_get_proxy_socket.return_value.__enter__.return_value = mock_socket
        
        # Call the function
        result = reverse_dns_lookup("192.168.1.1")
        
        # Assertions
        mock_get_proxy_socket.assert_called_once()
        mock_socket.gethostbyaddr.assert_called_with("192.168.1.1")
        self.assertEqual(result, "example.com")
    
    @patch('app.finddomains.get_proxy_socket')
    def test_check_hostname_resolvematch(self, mock_get_proxy_socket):
        # Setup mock
        mock_socket = MagicMock()
        mock_socket.gethostbyname.return_value = "192.168.1.1"
        mock_get_proxy_socket.return_value.__enter__.return_value = mock_socket
        
        # Call the function
        hostnames = ["example.com", "test.com"]
        result = check_hostname_resolvematch(hostnames, "192.168.1.1")
        
        # Assertions
        self.assertEqual(mock_get_proxy_socket.call_count, 2)
        self.assertEqual(mock_socket.gethostbyname.call_count, 2)
        self.assertEqual(result, ["example.com", "test.com"])

if __name__ == '__main__':
    unittest.main() 