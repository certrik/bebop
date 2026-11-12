import unittest
from unittest.mock import patch

from app import httpdowngrade


class FakeSocket:
    """Minimal socket stand-in: hands back a scripted response then EOF."""

    def __init__(self, response_bytes):
        self._response = response_bytes
        self._served = False
        self.sent = b''

    def sendall(self, data):
        self.sent += data

    def recv(self, _bufsize):
        if self._served:
            return b''
        self._served = True
        return self._response

    def close(self):
        pass


class TestBuildRequest(unittest.TestCase):
    def test_is_http_1_0_without_host_header(self):
        req = httpdowngrade.build_request('/')
        text = req.decode()
        # the two defining properties of this probe
        self.assertIn('GET / HTTP/1.0', text)
        self.assertNotIn('\r\nHost:', text)
        self.assertNotIn('\r\nhost:', text.lower())
        # well-formed: terminated by a blank line
        self.assertTrue(text.endswith('\r\n\r\n'))

    def test_defaults_path_to_root(self):
        self.assertIn('GET / HTTP/1.0', httpdowngrade.build_request('').decode())

    def test_preserves_path_and_query(self):
        self.assertIn('GET /app?x=1 HTTP/1.0',
                      httpdowngrade.build_request('/app?x=1').decode())


class TestParseResponse(unittest.TestCase):
    def test_parses_status_headers_and_body(self):
        raw = (b'HTTP/1.1 200 OK\r\n'
               b'Server: nginx/1.18.0\r\n'
               b'Content-Type: text/html\r\n'
               b'\r\n'
               b'<html>body</html>')
        parsed = httpdowngrade.parse_response(raw)
        self.assertEqual(parsed['http_version'], 'HTTP/1.1')
        self.assertEqual(parsed['status_code'], 200)
        self.assertEqual(parsed['status_reason'], 'OK')
        self.assertEqual(parsed['headers']['server'], 'nginx/1.18.0')
        self.assertEqual(parsed['body'], b'<html>body</html>')

    def test_folds_duplicate_headers(self):
        raw = (b'HTTP/1.0 200 OK\r\n'
               b'Set-Cookie: a=1\r\n'
               b'Set-Cookie: b=2\r\n\r\n')
        parsed = httpdowngrade.parse_response(raw)
        self.assertEqual(parsed['headers']['set-cookie'], 'a=1, b=2')

    def test_returns_none_for_non_http(self):
        self.assertIsNone(httpdowngrade.parse_response(b'not http at all'))
        self.assertIsNone(httpdowngrade.parse_response(b''))


class TestExtractTitle(unittest.TestCase):
    def test_extracts_and_collapses_whitespace(self):
        self.assertEqual(
            httpdowngrade._extract_title(b'<html><head><TITLE> Default\n  Page </TITLE>'),
            'Default Page')

    def test_none_when_absent(self):
        self.assertIsNone(httpdowngrade._extract_title(b'<html>no title here</html>'))


class TestCompareBaseline(unittest.TestCase):
    def test_flags_server_title_body_status_and_offsite_redirect(self):
        result = {
            'server': 'Apache',
            'title': 'Backend',
            'body_hash': {'sha256': 'bbb'},
            'status_code': 301,
            'location': 'https://origin.internal.example.net/',
        }
        baseline = {
            'server': 'cloudflare',
            'title': 'Fronted site',
            'body_sha256': 'aaa',
            'status_code': 200,
            'fqdn': 'example.onion',
        }
        diff = httpdowngrade.compare_baseline(result, baseline)
        self.assertTrue(diff['server_differs'])
        self.assertTrue(diff['title_differs'])
        self.assertTrue(diff['body_differs'])
        self.assertTrue(diff['status_differs'])
        self.assertTrue(diff['redirects_offsite'])

    def test_identical_response_shows_no_diff(self):
        result = {
            'server': 'nginx',
            'title': 'Same',
            'body_hash': {'sha256': 'aaa'},
            'status_code': 200,
            'location': None,
        }
        baseline = {
            'server': 'nginx',
            'title': 'Same',
            'body_sha256': 'aaa',
            'status_code': 200,
            'fqdn': 'example.onion',
        }
        diff = httpdowngrade.compare_baseline(result, baseline)
        self.assertFalse(any(diff.values()))

    def test_empty_baseline_is_safe(self):
        diff = httpdowngrade.compare_baseline({'server': 'nginx'}, None)
        self.assertFalse(any(diff.values()))


class TestMain(unittest.TestCase):
    def test_missing_host_returns_error_without_probing(self):
        result = httpdowngrade.main('notaurl', usetor=False)
        self.assertFalse(result['performed'])
        self.assertIsNotNone(result['error'])

    @patch('app.httpdowngrade._open_socket')
    def test_full_probe_over_plain_http(self, mock_open):
        raw = (b'HTTP/1.1 301 Moved Permanently\r\n'
               b'Server: Apache/2.4.41\r\n'
               b'Location: https://backend.corp-internal.net/\r\n'
               b'Content-Length: 40\r\n\r\n'
               b'<title>origin</title> see 45.33.32.156')
        fake = FakeSocket(raw)
        mock_open.return_value = fake

        baseline = {'server': 'cloudflare', 'fqdn': 'example.onion',
                    'status_code': 200, 'title': 'fronted'}
        result = httpdowngrade.main('http://example.onion/', usetor=False, baseline=baseline)

        # the request actually put on the wire is the downgraded, host-less one
        self.assertIn(b'HTTP/1.0', fake.sent)
        self.assertNotIn(b'Host:', fake.sent)

        self.assertTrue(result['performed'])
        self.assertFalse(result['host_header_sent'])
        self.assertFalse(result['sni_sent'])
        self.assertEqual(result['status_code'], 301)
        self.assertEqual(result['server'], 'Apache/2.4.41')
        self.assertEqual(result['location'], 'https://backend.corp-internal.net/')
        self.assertEqual(result['title'], 'origin')
        # origin indicators mined from the host-less response
        self.assertIn('45.33.32.156', result['indicators']['public_ips'])
        self.assertIn('backend.corp-internal.net', result['indicators']['hostnames'])
        # diffs vs the Host-ed baseline
        self.assertTrue(result['diff']['server_differs'])
        self.assertTrue(result['diff']['status_differs'])
        self.assertTrue(result['diff']['redirects_offsite'])

    @patch('app.httpdowngrade._open_socket')
    def test_unparseable_response_marks_not_performed(self, mock_open):
        mock_open.return_value = FakeSocket(b'garbage-not-http')
        result = httpdowngrade.main('http://example.onion/', usetor=False)
        self.assertFalse(result['performed'])
        self.assertEqual(result['error'], 'no parseable HTTP response')

    @patch('app.httpdowngrade._open_socket', side_effect=OSError('connection refused'))
    def test_connection_failure_is_captured(self, _mock_open):
        result = httpdowngrade.main('http://example.onion/', usetor=False)
        self.assertFalse(result['performed'])
        self.assertIn('connection refused', result['error'])


if __name__ == '__main__':
    unittest.main()
