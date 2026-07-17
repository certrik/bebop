#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal source-IP logging listener for bebop's out-of-band (OOB) callback deanon.

Run this on a BURNER host. It records the source IP of every inbound request
against the token embedded in that request, and serves the recorded hits as JSON
so bebop can poll them (`BEBOP_OOB_POLL_URL`).

Token is read from either:
  * the URL path  - path style:      http://HOST/<token>          (single A record)
  * the leftmost Host label - subdomain style: http://<token>.HOST (needs *.HOST)

No third-party dependencies - Python 3 standard library only.

    python3 oob_listener.py            # listen on 0.0.0.0:80
    python3 oob_listener.py 8080       # custom port
    OOB_TRUST_XFF=1 python3 oob_listener.py   # trust X-Forwarded-For (behind a proxy)

==============================  OPSEC WARNING  ================================
Whatever runs this is EXPOSED TO THE TARGET. When the origin calls back, it
connects here over clearnet and this host's IP is what the operator sees. Use
throwaway, anonymously-funded infrastructure that is NEVER reused and has no
ties to your identity. Put nothing else on this box. Read OPSEC.md. Only use
this against systems you are explicitly authorised to test.
=============================================================================
"""
import os
import sys
import json
import time
import threading
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

POLL_PREFIX = '/__hits__'          # bebop polls this; never treated as a callback
_HITS = {}                         # token -> [hit, ...]
_LOCK = threading.Lock()
_TRUST_XFF = os.environ.get('OOB_TRUST_XFF', '').lower() in ('1', 'true', 'yes', 'on')


def _client_ip(handler):
    # Only trust XFF when explicitly enabled (i.e. you run behind a proxy you
    # control). Otherwise XFF is attacker-controlled and would let a target
    # forge a decoy source IP.
    if _TRUST_XFF:
        xff = handler.headers.get('X-Forwarded-For')
        if xff:
            return xff.split(',')[0].strip()
    return handler.client_address[0]


class Handler(BaseHTTPRequestHandler):
    server_version = 'nginx'       # bland banner; do not advertise this tool
    def log_message(self, *a):     # quiet; we do our own logging
        pass

    def _token(self):
        # Path style takes precedence: /<token>  (works for domain and raw-IP
        # hosts alike, so a raw-IP Host is never mistaken for a subdomain).
        seg = urlparse(self.path).path.lstrip('/').split('/')[0]
        if seg:
            return seg
        # Subdomain style: <token>.oob.example.net -> first label. Only for real
        # hostnames (a raw-IP Host has >2 labels but no subdomain token).
        host = (self.headers.get('Host') or '').split(':')[0]
        try:
            import ipaddress
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        labels = [l for l in host.split('.') if l]
        return labels[0] if len(labels) >= 3 else None

    def _record(self):
        token = self._token()
        if not token:
            return
        hit = {
            'token': token,
            'remote-address': _client_ip(self),
            'protocol': 'http',
            'method': self.command,
            'timestamp': int(time.time()),
            'host': self.headers.get('Host'),
            'path': self.path,
            'user-agent': self.headers.get('User-Agent'),
        }
        with _LOCK:
            _HITS.setdefault(token, []).append(hit)
        sys.stderr.write('[callback] token=%s src=%s ua=%r\n'
                         % (token, hit['remote-address'], hit['user-agent']))

    def _serve_hits(self):
        token = (parse_qs(urlparse(self.path).query).get('token') or [''])[0]
        with _LOCK:
            data = list(_HITS.get(token, []))
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ok(self):
        # A tiny, generic response - a pingback fetch just needs a 200 body.
        body = b'<html><body>ok</body></html>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _dispatch(self):
        if urlparse(self.path).path.startswith(POLL_PREFIX):
            return self._serve_hits()
        self._record()
        return self._ok()

    # Record on every method a fetcher might use.
    do_GET = do_POST = do_HEAD = do_PUT = do_OPTIONS = _dispatch


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    server = ThreadingHTTPServer(('0.0.0.0', port), Handler)
    sys.stderr.write('oob listener on 0.0.0.0:%d  (poll: %s?token=...)  trust_xff=%s\n'
                     % (port, POLL_PREFIX, _TRUST_XFF))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == '__main__':
    main()
