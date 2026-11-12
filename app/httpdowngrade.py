#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
No-Host HTTP/1.0 downgrade probe.

CDNs and reverse proxies (Cloudflare, generic nginx/Apache virtual-host front
ends) route a request to the right backend by its ``Host`` header - and, over
TLS, by the SNI in the ClientHello. bebop's normal fetch sends both, so it sees
whatever the front end is configured to show for that hostname.

This probe deliberately sends neither. It opens a raw socket (over the Tor SOCKS
proxy, exactly like the JARM probe) and issues::

    GET / HTTP/1.0
    User-Agent: ...
    Accept: */*
    Connection: close

with **no Host header** and, for HTTPS, **no SNI**. An HTTP/1.0 request carries
no host context at all, so a server that multiplexes virtual hosts has to fall
back to its *default* vhost. That default is frequently the real origin
application, a catch-all error page, or a status/landing page that the fronted
hostname never exposes - and it often differs from the baseline in ways that
point straight at the backend:

  * a different ``Server`` banner or status code than the Host-ed response;
  * a ``Location`` redirect to the origin's real hostname;
  * the origin's real IP / internal hostnames echoed in the body or headers
    (mined with the same origin-indicator extractor the config checks use);
  * a wholly different default page (title / body hash) to pivot on.

The probe is read-only - it only sends a single, syntactically-valid GET - but
because it strips the routing context it can reach the origin behind the front,
which is the whole point. Results are diffed against the baseline (the normal
Host-ed response) so the caller can tell at a glance whether the front end
leaked something.
'''
import re
import ssl
import socket
import logging
from urllib.parse import urlparse

from app.utilities import useragentstr
from app.contentleak import compute_body_hash
from app.configcheck import extract_origin_indicators

log = logging.getLogger(__name__)

# cap how much of the body we read/hash so a chunk-less HTTP/1.0 stream from a
# huge or deliberately-slow origin can't balloon memory or stall the scan.
_MAX_BODY = 512 * 1024
_TITLE_RE = re.compile(rb'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)


def _open_socket(host, port, usetor, timeout):
    '''Open a plain TCP socket to host:port, over Tor when requested.

    Mirrors app/jarm.py: rdns=True lets the Tor proxy resolve .onion names so
    the probe reaches hidden services the same way the rest of bebop does.
    '''
    if usetor:
        import socks
        from app.utilities import getproxyvalue
        addr, pport = getproxyvalue()
        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, addr, int(pport), rdns=True)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def build_request(path, user_agent=useragentstr):
    '''Build the raw request line + headers - HTTP/1.0 and no Host header.

    Returns bytes ready to put on the wire. Kept separate from the socket code
    so the "downgraded, host-less" contract can be asserted in tests.
    '''
    if not path:
        path = '/'
    lines = [
        f'GET {path} HTTP/1.0',
        f'User-Agent: {user_agent}',
        'Accept: */*',
        'Connection: close',
        '',
        '',
    ]
    return '\r\n'.join(lines).encode('utf-8', 'ignore')


def _recv_all(sock, limit=_MAX_BODY):
    '''Read until the server closes the connection (HTTP/1.0) or we hit limit.

    Returns ``(data, truncated)``. ``truncated`` is True when the stream was cut
    off at ``limit`` so callers know the body is incomplete and must not be
    compared byte-for-byte against a full-body baseline.
    '''
    chunks = []
    total = 0
    truncated = False
    while True:
        try:
            buf = sock.recv(16384)
        except socket.timeout:
            break
        if not buf:
            break
        chunks.append(buf)
        total += len(buf)
        if total >= limit:
            truncated = True
            break
    return b''.join(chunks), truncated


def parse_response(raw):
    '''Parse a raw HTTP/1.0 response into version/status/headers/body.

    Pure byte-wrangling (no socket), so it is unit-testable. Returns None when
    the bytes don't start with an HTTP status line.
    '''
    if not raw:
        return None
    head, _, body = raw.partition(b'\r\n\r\n')
    if b'\r\n\r\n' not in raw and b'\n\n' in raw:
        # some servers use bare LF line endings
        head, _, body = raw.partition(b'\n\n')
    head_lines = head.replace(b'\r\n', b'\n').split(b'\n')
    status_line = head_lines[0].decode('iso-8859-1', 'replace').strip()
    m = re.match(r'^(HTTP/\d\.\d)\s+(\d{3})\s*(.*)$', status_line)
    if not m:
        return None
    http_version, code, reason = m.group(1), int(m.group(2)), m.group(3).strip()
    headers = {}
    for line in head_lines[1:]:
        decoded = line.decode('iso-8859-1', 'replace')
        if ':' not in decoded:
            continue
        name, value = decoded.split(':', 1)
        name = name.strip().lower()
        value = value.strip()
        # fold duplicate headers (e.g. multiple Set-Cookie) rather than lose them
        if name in headers:
            headers[name] = headers[name] + ', ' + value
        else:
            headers[name] = value
    return {
        'http_version': http_version,
        'status_code': code,
        'status_reason': reason,
        'headers': headers,
        'body': body,
    }


def _normalize_title(text):
    '''Collapse whitespace so titles from different parsers compare equal.

    Shared by the probe's own title extraction and by ``compare_baseline`` so a
    purely-cosmetic whitespace difference between the raw baseline title and the
    probe title is never mistaken for a real page difference.
    '''
    if not text:
        return ''
    return re.sub(r'\s+', ' ', text).strip()


def _extract_title(body_bytes):
    m = _TITLE_RE.search(body_bytes or b'')
    if not m:
        return None
    title = _normalize_title(m.group(1).decode('utf-8', 'replace'))
    return title or None


def compare_baseline(result, baseline):
    '''Diff a probe result against the baseline (normal Host-ed response).

    ``baseline`` is a dict that may carry ``server``, ``title``,
    ``body_sha256`` and ``status_code``. Returns a dict describing what the
    host-less response changed - an empty-ish dict means the front end gave the
    same answer with or without the Host header (no leak).
    '''
    diff = {
        'server_differs': False,
        'title_differs': False,
        'body_differs': False,
        'status_differs': False,
        'redirects_offsite': False,
    }
    if not baseline:
        return diff
    b_server = (baseline.get('server') or '').strip().lower()
    r_server = (result.get('server') or '').strip().lower()
    if b_server and r_server and b_server != r_server:
        diff['server_differs'] = True

    b_title = _normalize_title(baseline.get('title'))
    r_title = _normalize_title(result.get('title'))
    if b_title and r_title and b_title != r_title:
        diff['title_differs'] = True

    # Only compare bodies when the probe captured a complete body. The baseline
    # sha256 is over the full (decompressed) Host-ed response, whereas the probe
    # body is read raw off the socket and capped at _MAX_BODY; comparing a
    # truncated body against a full-body hash would always report a difference.
    b_hash = baseline.get('body_sha256')
    r_hash = (result.get('body_hash') or {}).get('sha256')
    if b_hash and r_hash and not result.get('body_truncated') and b_hash != r_hash:
        diff['body_differs'] = True

    b_code = baseline.get('status_code')
    r_code = result.get('status_code')
    if b_code and r_code and b_code != r_code:
        diff['status_differs'] = True

    # a Location that points at a different host is a classic origin giveaway
    loc = result.get('location')
    if loc:
        loc_host = urlparse(loc).hostname
        if loc_host and baseline.get('fqdn') and loc_host.lower() != baseline['fqdn'].lower():
            diff['redirects_offsite'] = True
    return diff


def main(target, usetor=True, baseline=None, timeout=30):
    '''
    Probe ``target`` with a downgraded, host-less HTTP/1.0 request.

    Returns a findings dict (always, even on failure, with ``performed`` saying
    whether a response came back) so the reporting layer can show the probe ran.
    '''
    parsed = urlparse(target)
    scheme = (parsed.scheme or 'http').lower()
    host = parsed.hostname
    is_tls = scheme == 'https'
    port = parsed.port or (443 if is_tls else 80)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    result = {
        'performed': False,
        'target': target,
        'host': host,
        'port': port,
        'tls': is_tls,
        'sni_sent': False,          # deliberately never send SNI
        'host_header_sent': False,  # deliberately never send Host
        'request_line': f'GET {path} HTTP/1.0',
        'http_version': None,
        'status_code': None,
        'status_reason': None,
        'server': None,
        'location': None,
        'content_type': None,
        'content_length': None,
        'title': None,
        'body_hash': None,
        'body_truncated': False,
        'headers': {},
        'indicators': {'public_ips': [], 'private_ips': [], 'hostnames': []},
        'diff': {},
        'error': None,
    }

    if not host:
        result['error'] = 'could not parse host from target'
        log.warning('httpdowngrade: %s', result['error'])
        return result

    log.info('httpdowngrade: probing %s with HTTP/1.0 and no Host header (tls=%s, tor=%s)',
             target, is_tls, usetor)

    sock = None
    try:
        sock = _open_socket(host, port, usetor, timeout)
        if is_tls:
            ctx = ssl.create_default_context()
            # strip the TLS-layer host context too: no SNI, and accept whatever
            # certificate the default vhost presents (we only read the response).
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)  # no server_hostname => no SNI
        sock.sendall(build_request(path))
        raw, body_truncated = _recv_all(sock)
    except Exception as e:
        result['error'] = str(e)
        log.info('httpdowngrade: probe failed for %s - %s', target, e)
        return result
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    parsed_resp = parse_response(raw)
    if not parsed_resp:
        result['error'] = 'no parseable HTTP response'
        log.info('httpdowngrade: no parseable response from %s', target)
        return result

    result['performed'] = True
    result['http_version'] = parsed_resp['http_version']
    result['status_code'] = parsed_resp['status_code']
    result['status_reason'] = parsed_resp['status_reason']
    headers = parsed_resp['headers']
    result['headers'] = headers
    result['server'] = headers.get('server')
    result['location'] = headers.get('location')
    result['content_type'] = headers.get('content-type')
    try:
        result['content_length'] = int(headers['content-length']) if 'content-length' in headers else None
    except (TypeError, ValueError):
        result['content_length'] = None

    body = parsed_resp['body'] or b''
    result['body_truncated'] = body_truncated
    result['title'] = _extract_title(body)
    if body:
        result['body_hash'] = compute_body_hash(body)

    # mine the default-vhost response for the origin's real addressing, the same
    # way matched config leaks are mined. Headers (Location, Via, X-Backend, ...)
    # and the body both get scanned.
    indicator_text = '\n'.join(f'{k}: {v}' for k, v in headers.items())
    indicator_text += '\n' + body.decode('utf-8', 'replace')
    result['indicators'] = extract_origin_indicators(indicator_text)

    result['diff'] = compare_baseline(result, baseline)

    log.info('httpdowngrade: %s => %s %s (server=%s, location=%s)',
             target, result['status_code'], result['status_reason'],
             result['server'], result['location'])
    if any(result['diff'].values()):
        log.warning('httpdowngrade: host-less response DIFFERS from baseline for %s: %s',
                    target, {k: v for k, v in result['diff'].items() if v})
    if result['indicators']['public_ips'] or result['indicators']['hostnames']:
        log.warning('httpdowngrade: host-less response exposes origin indicators: %s',
                    result['indicators']['public_ips'] + result['indicators']['hostnames'])

    return result
