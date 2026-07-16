import unittest
from unittest.mock import patch
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import jarm


class TestJarm(unittest.TestCase):
    @patch('app.jarm._JARM_AVAILABLE', False)
    def test_unavailable_returns_none(self):
        # When pyjarm isn't installed the feature degrades to None, never crashes.
        self.assertIsNone(jarm.compute_jarm('example.onion', 443))

    @unittest.skipUnless(jarm._JARM_AVAILABLE, 'pyjarm not installed')
    @patch('app.jarm._probe')
    def test_compute_assembles_and_hashes(self, mock_probe):
        mock_probe.return_value = b'\x16\x03\x03\x00'  # opaque; parsing is patched
        with patch('app.jarm.Scanner') as S, patch('app.jarm.Hasher') as H, \
                patch('app.jarm._failure_hash', lambda: '0' * 62):
            S._generate_packets.return_value = [('p1', b'aa'), ('p2', b'bb')]
            S._parse_server_hello.side_effect = lambda hello, pkt: 'R'
            H.jarm.return_value = 'abcd' + '0' * 58
            out = jarm.compute_jarm('h', 443, usetor=False)
            self.assertEqual(out, 'abcd' + '0' * 58)
            # results from both probes get joined and hashed
            H.jarm.assert_called_once_with('R,R')

    @unittest.skipUnless(jarm._JARM_AVAILABLE, 'pyjarm not installed')
    @patch('app.jarm._probe', return_value=None)
    def test_all_failure_returns_none(self, _):
        with patch('app.jarm.Scanner') as S, patch('app.jarm.Hasher') as H, \
                patch('app.jarm._failure_hash', lambda: 'FAILHASH'):
            S._generate_packets.return_value = [('p1', b'aa')]
            S._parse_server_hello.return_value = ''
            H.jarm.return_value = 'FAILHASH'  # every probe failed
            self.assertIsNone(jarm.compute_jarm('h', 443, usetor=False))

    @unittest.skipUnless(jarm._JARM_AVAILABLE, 'pyjarm not installed')
    def test_matches_pyjarm_reference_against_local_tls_server(self):
        '''
        Definitive correctness check: our SOCKS-capable transport must produce
        the exact JARM that pyjarm's own reference scanner produces against the
        same server.
        '''
        try:
            import ssl
            import socket
            import threading
            import datetime
            import tempfile
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from jarm.scanner.scanner import Scanner
        except Exception as e:  # pragma: no cover
            self.skipTest(f'TLS test prerequisites unavailable: {e}')

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'localhost')])
        cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime(2020, 1, 1))
                .not_valid_after(datetime.datetime(2030, 1, 1))
                .sign(key, hashes.SHA256()))
        d = tempfile.mkdtemp()
        cpath, kpath = os.path.join(d, 'c.pem'), os.path.join(d, 'k.pem')
        with open(cpath, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(kpath, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cpath, kpath)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', 0))
        srv.listen(50)
        port = srv.getsockname()[1]
        state = {'stop': False}

        def serve():
            while not state['stop']:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    break

                def handle(c):
                    try:
                        c.settimeout(5)
                        ctx.wrap_socket(c, server_side=True).close()
                    except Exception:
                        try:
                            c.close()
                        except Exception:
                            pass
                threading.Thread(target=handle, args=(conn,), daemon=True).start()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            # proxy='ignore' so pyjarm doesn't pick up an ambient HTTPS_PROXY
            expected = Scanner.scan('127.0.0.1', port, proxy='ignore', suppress=True)[0]
            mine = jarm.compute_jarm('127.0.0.1', port, usetor=False, timeout=8)
        finally:
            state['stop'] = True
            srv.close()

        self.assertIsNotNone(mine)
        self.assertEqual(len(mine), 62)
        self.assertNotEqual(mine, '0' * 62)
        self.assertEqual(mine, expected)


if __name__ == '__main__':
    unittest.main()
