import unittest
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import contentleak


SAMPLE_HTML = """
<html><head>
  <title>Secret Market</title>
  <link rel="canonical" href="https://realmarket.example/home">
  <link rel="stylesheet" href="https://cdn.realcorp.example/app.css">
  <style>body { background: url('https://assets.realcorp.example/bg.png'); }</style>
</head><body>
  <img src="https://img.realcorp.example/logo.png">
  <script src="/local.js"></script>
  <script src="https://analytics.realcorp.example/track.js"></script>
  <a href="https://twitter.com/operator">twitter</a>
  <a href="mailto:admin@realcorp.example">contact</a>
  Reach us at ops@realcorp.example
  -----BEGIN PGP PUBLIC KEY BLOCK-----
  mQINBFxyzKEY==
  -----END PGP PUBLIC KEY BLOCK-----
</body></html>
"""


def make_request(html, url='http://secretmarketxxxx.onion/', headers=None):
    obj = MagicMock()
    obj.text = html
    obj.content = html.encode('utf-8')
    obj.url = url
    obj.headers = headers or {}
    return obj


class TestContentLeak(unittest.TestCase):
    def test_clearnet_resources_detected(self):
        leaks = contentleak.extract_clearnet_resources(SAMPLE_HTML, 'secretmarketxxxx.onion')
        hosts = {l['host'] for l in leaks}
        # Resource-loading clearnet hosts should all be found
        self.assertIn('cdn.realcorp.example', hosts)
        self.assertIn('img.realcorp.example', hosts)
        self.assertIn('analytics.realcorp.example', hosts)
        self.assertIn('assets.realcorp.example', hosts)  # from CSS url()
        # the relative /local.js and the onion itself must NOT be reported
        self.assertNotIn('', hosts)
        self.assertNotIn('secretmarketxxxx.onion', hosts)

    def test_outbound_links_separate_from_resources(self):
        outbound = contentleak.extract_outbound_links(SAMPLE_HTML, 'secretmarketxxxx.onion')
        self.assertIn('twitter.com', outbound)
        # a loaded resource host is not an anchor link
        self.assertNotIn('img.realcorp.example', outbound)

    def test_onion_location_header_and_canonical(self):
        req = make_request(SAMPLE_HTML, headers={'Onion-Location': 'http://twin.onion/'})
        found = contentleak.extract_onion_location(req, SAMPLE_HTML)
        self.assertEqual(found['onion_location'], 'http://twin.onion/')
        self.assertIn('https://realmarket.example/home', found['canonical_links'])

    def test_pgp_key_extraction(self):
        keys = contentleak.extract_pgp_keys(SAMPLE_HTML)
        self.assertEqual(len(keys), 1)
        self.assertEqual(len(keys[0]['id']), 16)

    def test_email_extraction(self):
        emails = contentleak.extract_emails(SAMPLE_HTML)
        self.assertIn('admin@realcorp.example', emails)
        self.assertIn('ops@realcorp.example', emails)

    def test_body_hash_stable(self):
        h1 = contentleak.compute_body_hash('hello world')
        h2 = contentleak.compute_body_hash(b'hello world')
        self.assertEqual(h1['mmh3'], h2['mmh3'])
        self.assertEqual(h1['md5'], h2['md5'])
        self.assertEqual(h1['sha256'], h2['sha256'])
        self.assertEqual(len(h1['md5']), 32)
        self.assertEqual(len(h1['sha256']), 64)

    @patch('app.contentleak.query_validin_pivot')
    @patch('app.contentleak.query_modat')
    @patch('app.contentleak.query_zoomeye')
    @patch('app.contentleak.query_shodan')
    def test_main_pivots_body_hash(self, mock_shodan, mock_zoomeye, mock_modat, mock_validin):
        req = make_request(SAMPLE_HTML, headers={'Onion-Location': 'http://twin.onion/'})
        findings = contentleak.main(req)
        # body-hash pivots fired on each engine's indexed form: Shodan (mmh3),
        # ZoomEye (md5), Modat (web.html.sha256), Validin (sha1).
        self.assertTrue(mock_shodan.called)
        self.assertTrue(mock_zoomeye.called)
        self.assertTrue(mock_modat.called)
        self.assertTrue(mock_validin.called)
        self.assertTrue(mock_shodan.call_args[0][0].startswith('http.html_hash:'))
        self.assertEqual(mock_zoomeye.call_args[0][0], 'body_hash:' + findings['body_hash']['md5'])
        self.assertEqual(mock_modat.call_args[0][0], 'web.html.sha256="' + findings['body_hash']['sha256'] + '"')
        self.assertEqual(mock_validin.call_args[0][0], findings['body_hash']['sha1'])
        # findings surface the high-signal items
        self.assertTrue(findings['clearnet_resources'])
        self.assertEqual(findings['onion_location']['onion_location'], 'http://twin.onion/')
        self.assertTrue(findings['pgp_keys'])
        self.assertTrue(findings['emails'])
        self.assertIsNotNone(findings['body_hash'])


if __name__ == '__main__':
    unittest.main()
