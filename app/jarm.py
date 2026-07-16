#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
JARM active TLS server fingerprinting.

JARM sends 10 specifically-crafted TLS Client Hellos and hashes the server's
responses into a 62-character fingerprint. Because the fingerprint depends on
the server's TLS stack and configuration rather than its address, a hidden
service and its exposed clearnet origin - if they share a TLS terminator -
produce the same JARM. All of Shodan (ssl.jarm), ZoomEye (ssl.jarm), Modat
(tls.jarm) and Censys index it, so a match is a strong deanonymisation pivot.

The byte-exact packet construction, ServerHello parsing and hashing come from
the maintained reference implementation (pyjarm); only the transport is
replaced here so probes can be routed through the Tor SOCKS proxy the way the
rest of bebop reaches .onion targets.
'''
import socket
import logging

from app.utilities import getproxyvalue

log = logging.getLogger(__name__)

try:
    from jarm.scanner.scanner import Scanner
    from jarm.hashing.hashing import Hasher
    from jarm.constants import TOTAL_FAILURE
    _JARM_AVAILABLE = True
except Exception:  # pragma: no cover - pyjarm is an optional dependency
    _JARM_AVAILABLE = False


def _failure_hash():
    '''The fingerprint returned when every probe fails (target speaks no TLS).
    Computed lazily: calling Hasher.jarm() installs a root log handler, so we
    avoid doing it at import time where it would clobber bebop's logging setup.'''
    if not _JARM_AVAILABLE:
        return '0' * 62
    return Hasher.jarm(TOTAL_FAILURE)


def _open_socket(host, port, usetor, timeout):
    if usetor:
        import socks
        addr, pport = getproxyvalue()
        sock = socks.socksocket()
        # rdns=True so .onion names are resolved by the Tor proxy, not locally.
        sock.set_proxy(socks.SOCKS5, addr, int(pport), rdns=True)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def _probe(host, port, payload, usetor, timeout):
    '''Send one JARM Client Hello and return up to 1484 bytes of the response.'''
    sock = None
    try:
        sock = _open_socket(host, port, usetor, timeout)
        sock.sendall(payload)
        # Match pyjarm's single read(1484): the ServerHello arrives in the first
        # flight, so one recv captures what JARM needs without stalling until the
        # timeout waiting for handshake data the client never sends.
        return sock.recv(1484)
    except Exception as e:
        log.debug('jarm: probe failed for %s:%s - %s', host, port, e)
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def compute_jarm(host, port=443, usetor=True, timeout=15):
    '''
    Return the 62-character JARM fingerprint for host:port, or None if JARM is
    unavailable or the target produced no usable TLS response.
    '''
    if not _JARM_AVAILABLE:
        log.warning('jarm: pyjarm not installed - skipping JARM fingerprint')
        return None

    results = []
    for name, payload in Scanner._generate_packets(dest_host=host, dest_port=port):
        hello = _probe(host, port, payload, usetor, timeout)
        results.append(Scanner._parse_server_hello(hello, (name, payload)))

    fingerprint = Hasher.jarm(','.join(results))
    if fingerprint == _failure_hash():
        log.info('jarm: no TLS response from %s:%s', host, port)
        return None
    return fingerprint
