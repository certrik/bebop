#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import socket
import ssl
import hashlib
import struct
from app.subprocessors import query_shodan, query_censys, query_zoomeye, query_modat, query_validin_pivot
from app.jarm import compute_jarm
from app.utilities import getsocks

logger = logging.getLogger('bebop')


def get_tls_versions():
    """
    Get list of TLS versions to probe
    """
    versions = []

    # TLS 1.0
    if hasattr(ssl, 'PROTOCOL_TLSv1'):
        versions.append(('TLS 1.0', ssl.PROTOCOL_TLSv1))

    # TLS 1.1
    if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
        versions.append(('TLS 1.1', ssl.PROTOCOL_TLSv1_1))

    # TLS 1.2
    if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
        versions.append(('TLS 1.2', ssl.PROTOCOL_TLSv1_2))

    # TLS 1.3
    if hasattr(ssl, 'PROTOCOL_TLS'):
        versions.append(('TLS 1.3', ssl.PROTOCOL_TLS))

    return versions


def extract_cipher_info(cipher):
    """
    Extract and format cipher suite information
    """
    if not cipher:
        return None

    return {
        'name': cipher[0] if len(cipher) > 0 else None,
        'protocol': cipher[1] if len(cipher) > 1 else None,
        'bits': cipher[2] if len(cipher) > 2 else None
    }


def probe_tls_connection(hostname, port, tls_version, usetor=True):
    """
    Probe TLS connection and extract handshake details
    """
    try:
        context = ssl.SSLContext(tls_version[1])
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Create socket with optional SOCKS proxy
        if usetor:
            try:
                import socks
                sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                proxy = getsocks()
                if proxy and 'socks5' in proxy.get('http', ''):
                    # Extract proxy host and port
                    import re
                    match = re.search(r'socks5h?://([^:]+):(\d+)', proxy['http'])
                    if match:
                        proxy_host, proxy_port = match.groups()
                        # rdns=True so .onion hostnames resolve via the Tor proxy
                        sock.set_proxy(socks.SOCKS5, proxy_host, int(proxy_port), rdns=True)
            except ImportError:
                logger.warning("PySocks not available for Tor routing in TLS probe")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(10)

        # Wrap socket with SSL
        wrapped_socket = context.wrap_socket(sock, server_hostname=hostname)
        wrapped_socket.connect((hostname, port))

        # Get cipher info
        cipher = wrapped_socket.cipher()
        cipher_info = extract_cipher_info(cipher)

        # Get protocol version
        protocol_version = wrapped_socket.version()

        # Get compression (should be None for modern TLS)
        compression = wrapped_socket.compression()

        wrapped_socket.close()

        return {
            'version': tls_version[0],
            'cipher': cipher_info,
            'protocol_negotiated': protocol_version,
            'compression': compression,
            'success': True
        }

    except ssl.SSLError as e:
        logger.debug(f"TLS {tls_version[0]} probe failed: {e}")
        return {
            'version': tls_version[0],
            'success': False,
            'error': str(e)
        }
    except Exception as e:
        logger.debug(f"TLS {tls_version[0]} probe error: {e}")
        return {
            'version': tls_version[0],
            'success': False,
            'error': str(e)
        }


def compute_cipher_suite_hash(cipher_suites):
    """
    Compute a simple hash of cipher suite preferences
    This is a simplified version of JA3S (server fingerprint)
    """
    if not cipher_suites:
        return None

    # Create a string representation of cipher suites
    cipher_string = ','.join([c['name'] for c in cipher_suites if c and c.get('name')])

    # Compute MD5 hash
    md5_hash = hashlib.md5(cipher_string.encode()).hexdigest()

    return md5_hash


def analyze_tls_configuration(tls_results):
    """
    Analyze TLS configuration for security issues and fingerprinting
    """
    findings = {
        'supported_versions': [],
        'preferred_ciphers': [],
        'weak_configs': [],
        'fingerprint': None
    }

    for result in tls_results:
        if result['success']:
            findings['supported_versions'].append(result['version'])

            if result.get('cipher'):
                findings['preferred_ciphers'].append({
                    'version': result['version'],
                    'cipher': result['cipher']
                })

            # Check for weak configurations
            if result['version'] in ['TLS 1.0', 'TLS 1.1']:
                findings['weak_configs'].append(f"Outdated protocol supported: {result['version']}")
                logger.warning(f"Weak TLS version supported: {result['version']}")

            if result.get('compression'):
                findings['weak_configs'].append("TLS compression enabled (CRIME vulnerability)")
                logger.warning("TLS compression is enabled - CRIME vulnerability")

    # Compute fingerprint from cipher preferences
    if findings['preferred_ciphers']:
        fingerprint = compute_cipher_suite_hash(findings['preferred_ciphers'])
        findings['fingerprint'] = fingerprint

    return findings


def extract_cert_fingerprints(hostname, port, usetor=True):
    """
    Extract certificate-based fingerprints
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Create socket
        if usetor:
            try:
                import socks
                sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                proxy = getsocks()
                if proxy and 'socks5' in proxy.get('http', ''):
                    import re
                    match = re.search(r'socks5h?://([^:]+):(\d+)', proxy['http'])
                    if match:
                        proxy_host, proxy_port = match.groups()
                        # rdns=True so .onion hostnames resolve via the Tor proxy
                        sock.set_proxy(socks.SOCKS5, proxy_host, int(proxy_port), rdns=True)
            except ImportError:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(10)

        wrapped_socket = context.wrap_socket(sock, server_hostname=hostname)
        wrapped_socket.connect((hostname, port))

        # Get certificate
        cert_der = wrapped_socket.getpeercert(binary_form=True)

        # Compute fingerprints
        sha256_fingerprint = hashlib.sha256(cert_der).hexdigest()
        sha1_fingerprint = hashlib.sha1(cert_der).hexdigest()
        md5_fingerprint = hashlib.md5(cert_der).hexdigest()

        wrapped_socket.close()

        return {
            'sha256': sha256_fingerprint,
            'sha1': sha1_fingerprint,
            'md5': md5_fingerprint
        }

    except Exception as e:
        logger.error(f"Failed to extract certificate fingerprints: {e}")
        return None


def main(hostname, port=443, usetor=True, doshodan=True, docensys=True, dozoome=True, domodat=True, dovalidin=True):
    """
    Perform TLS/SSL fingerprinting on target
    """
    logger.info(f"Starting TLS fingerprinting for {hostname}:{port}")

    findings = {
        'tls_probes': [],
        'tls_analysis': None,
        'cert_fingerprints': None,
        'jarm': None
    }

    # JARM active fingerprint - a strong cross-host pivot indexed by every
    # engine (Shodan ssl.jarm, ZoomEye ssl.jarm, Modat tls.jarm, Censys).
    jarm_hash = compute_jarm(hostname, port, usetor=usetor)
    if jarm_hash:
        findings['jarm'] = jarm_hash
        logger.info(f"JARM fingerprint: {jarm_hash}")
        if doshodan:
            query_shodan(f'ssl.jarm:"{jarm_hash}"')
        if docensys:
            query_censys(f'host.services.jarm.fingerprint="{jarm_hash}"')
        if dozoome:
            query_zoomeye(f'ssl.jarm:"{jarm_hash}"')
        if domodat:
            query_modat(f'tls.jarm:{jarm_hash}')
        if dovalidin:
            query_validin_pivot(jarm_hash)

    # Probe different TLS versions
    tls_versions = get_tls_versions()

    for version in tls_versions:
        logger.debug(f"Probing {version[0]}...")
        result = probe_tls_connection(hostname, port, version, usetor)
        findings['tls_probes'].append(result)

        if result['success']:
            logger.info(f"{version[0]} supported - Cipher: {result.get('cipher', {}).get('name', 'Unknown')}")

    # Analyze TLS configuration
    analysis = analyze_tls_configuration(findings['tls_probes'])
    findings['tls_analysis'] = analysis

    if analysis['supported_versions']:
        logger.info(f"Supported TLS versions: {', '.join(analysis['supported_versions'])}")

    if analysis['fingerprint']:
        logger.info(f"TLS cipher fingerprint: {analysis['fingerprint']}")

        # Query threat intelligence platforms
        if doshodan:
            query_shodan(f'ssl.cipher.fingerprint:"{analysis["fingerprint"]}"')

        # Note: JA3S/JARM specific queries would go here if we implement full JA3S
        # For now, we're doing a simplified version

    # Extract certificate fingerprints
    cert_fps = extract_cert_fingerprints(hostname, port, usetor)
    if cert_fps:
        findings['cert_fingerprints'] = cert_fps
        logger.info(f"Certificate SHA256 fingerprint: {cert_fps['sha256']}")

        # Query using cert fingerprints
        if doshodan:
            query_shodan(f'ssl.cert.fingerprint.sha256:"{cert_fps["sha256"]}"')
        if docensys:
            query_censys(f'host.services.tls.certificates.leaf_data.fingerprint_sha256="{cert_fps["sha256"]}"')
        if dozoome:
            query_zoomeye(f'ssl.fingerprint:"{cert_fps["sha256"]}"')
        if domodat:
            query_modat(f'tls.fingerprint_sha256:{cert_fps["sha256"]}')
        if dovalidin:
            # Validin pivots certificates on the SHA1 fingerprint.
            query_validin_pivot(cert_fps['sha1'])

    return findings
