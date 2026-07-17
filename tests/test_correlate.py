import unittest
from unittest.mock import MagicMock
import sys
import os
import hashlib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import correlate


def fake_resp(html, server=None):
    r = MagicMock()
    r.content = html.encode('utf-8')
    r.text = html
    r.headers = {'server': server} if server else {}
    return r


ONION_HTML = "<html><head><title>Hidden Market</title></head><body>secret goods</body></html>"


class TestCorrelate(unittest.TestCase):
    def setUp(self):
        correlate.reset()

    def test_classification(self):
        self.assertEqual(correlate._classify('http.favicon.hash:123'), 'favicon')
        self.assertEqual(correlate._classify('ssl.jarm:"abc"'), 'jarm')
        self.assertEqual(correlate._classify('ssl.cert.serial:"999"'), 'cert_serial')
        self.assertEqual(correlate._classify('host.services.tls.certificates.leaf_data.fingerprint_sha256="x"'), 'cert_fp')
        self.assertEqual(correlate._classify('http.html_hash:42'), 'body')
        self.assertEqual(correlate._classify('title:"x"'), 'title')
        self.assertEqual(correlate._classify('hostname:"x"'), 'hostname')
        self.assertEqual(correlate._classify('pdns:resolution'), 'pdns')

    def test_ranking_by_distinct_categories(self):
        # strong candidate: 3 independent categories
        correlate.add_candidate('1.1.1.1', 'shodan', 'http.favicon.hash:1')
        correlate.add_candidate('1.1.1.1', 'censys', 'ssl.jarm:x')
        correlate.add_candidate('1.1.1.1', 'modat', 'cert.fingerprint.sha256="y"')
        # weak candidate: 1 category, seen twice
        correlate.add_candidate('2.2.2.2', 'shodan', 'http.favicon.hash:1')
        correlate.add_candidate('2.2.2.2', 'zoomeye', 'iconhash:1')

        ranked = correlate.ranked_candidates()
        self.assertEqual(ranked[0][0], '1.1.1.1')
        self.assertEqual(len(ranked[0][1]['categories']), 3)
        self.assertEqual(len(ranked[1][1]['categories']), 1)  # both favicon -> 1 category

    def test_confirm_body_match_is_confirmed(self):
        baseline = {'body_sha256': hashlib.sha256(ONION_HTML.encode()).hexdigest(),
                    'title': 'Hidden Market', 'server': 'nginx'}
        # candidate serves a byte-identical page over clearnet
        conf = correlate.confirm_candidate('origin.example', baseline,
                                           fetch_fn=lambda u: fake_resp(ONION_HTML, 'nginx'))
        self.assertEqual(conf['verdict'], 'CONFIRMED')
        self.assertIn('body_sha256', conf['matches'])
        self.assertTrue(conf['reachable'])

    def test_confirm_title_and_server_is_likely(self):
        baseline = {'body_sha256': 'DIFFERENT', 'title': 'Hidden Market', 'server': 'nginx'}
        conf = correlate.confirm_candidate('origin.example', baseline,
                                           fetch_fn=lambda u: fake_resp(ONION_HTML, 'nginx'))
        self.assertEqual(conf['verdict'], 'LIKELY')
        self.assertEqual(set(conf['matches']), {'title', 'server'})

    def test_confirm_no_match(self):
        baseline = {'body_sha256': 'DIFFERENT', 'title': 'Other', 'server': 'apache'}
        conf = correlate.confirm_candidate('decoy.example', baseline,
                                           fetch_fn=lambda u: fake_resp('<html><title>Other Site</title></html>', 'iis'))
        self.assertEqual(conf['verdict'], 'NO_MATCH')

    def test_confirm_unreachable(self):
        baseline = {'body_sha256': 'x'}
        conf = correlate.confirm_candidate('down.example', baseline, fetch_fn=lambda u: None)
        self.assertEqual(conf['verdict'], 'UNREACHABLE')
        self.assertFalse(conf['reachable'])

    def test_reverse_resolve_only_ips_and_confirms(self):
        baseline = {'body_sha256': hashlib.sha256(ONION_HTML.encode()).hexdigest(),
                    'title': 'Hidden Market', 'server': 'nginx'}
        results = [
            {'candidate': '5.5.5.5', 'categories': ['favicon', 'jarm'], 'category_count': 2,
             'sources': ['shodan'], 'confirmation': {'verdict': 'NO_MATCH', 'matches': []}},
            {'candidate': 'skip.example', 'categories': ['favicon'], 'category_count': 1,
             'sources': ['shodan'], 'confirmation': {'verdict': 'NO_MATCH', 'matches': []}},
        ]

        def resolver(ip):
            # urlscan/VT/etc. reverse-resolution: IP -> associated domains
            return ['origin.example'] if ip == '5.5.5.5' else []

        def fetch(u):
            return fake_resp(ONION_HTML, 'nginx') if 'origin.example' in u else None

        rev_map, new_records = correlate.reverse_resolve_and_confirm(
            results, resolver, baseline, fetch)

        # only the IP candidate was reverse-resolved, not the hostname
        self.assertEqual(rev_map, {'5.5.5.5': ['origin.example']})
        self.assertEqual(len(new_records), 1)
        rec = new_records[0]
        self.assertEqual(rec['candidate'], 'origin.example')
        self.assertEqual(rec['from_ip'], '5.5.5.5')
        self.assertEqual(rec['sources'], ['finddomains'])
        # the reverse-resolved domain serves the onion's page -> CONFIRMED
        self.assertEqual(rec['confirmation']['verdict'], 'CONFIRMED')
        # and it is now a registered candidate
        self.assertIn('origin.example', dict(correlate.ranked_candidates()))

    def test_end_to_end_ranks_confirmed_first(self):
        baseline = {'body_sha256': hashlib.sha256(ONION_HTML.encode()).hexdigest(),
                    'title': 'Hidden Market', 'server': 'nginx'}
        # decoy: strong correlation but serves different content
        correlate.add_candidate('decoy.example', 'shodan', 'http.favicon.hash:1')
        correlate.add_candidate('decoy.example', 'censys', 'ssl.jarm:x')
        # origin: weaker correlation but serves the real page
        correlate.add_candidate('origin.example', 'validin', 'validin:pivot')

        def fetch(u):
            if 'origin.example' in u:
                return fake_resp(ONION_HTML, 'nginx')
            return fake_resp('<html><title>nope</title></html>', 'iis')

        results = correlate.correlate_and_confirm(baseline, fetch_fn=fetch)
        # confirmed origin must rank ahead of the more-correlated but unconfirmed decoy
        self.assertEqual(results[0]['candidate'], 'origin.example')
        self.assertEqual(results[0]['confirmation']['verdict'], 'CONFIRMED')
        decoy = next(r for r in results if r['candidate'] == 'decoy.example')
        self.assertEqual(decoy['confirmation']['verdict'], 'NO_MATCH')


if __name__ == '__main__':
    unittest.main()
