#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import re
from urllib.parse import urlparse
from app.subprocessors import query_shodan, query_censys, query_zoomeye, query_fofa

logger = logging.getLogger('bebop')

common_headers = []
with open('common/headers.txt', 'r', encoding='utf-8') as common_headers_file:
    for line in common_headers_file:
        common_headers.append(line.strip())
    common_headers_file.close()


def parse_csp_header(csp_header):
    """
    Parse Content-Security-Policy header and extract domains
    Returns list of unique domains found in CSP directives
    """
    domains = set()

    # CSP directives that can contain URLs
    url_directives = [
        'default-src', 'script-src', 'style-src', 'img-src', 'connect-src',
        'font-src', 'object-src', 'media-src', 'frame-src', 'worker-src',
        'child-src', 'form-action', 'frame-ancestors', 'base-uri'
    ]

    # Split CSP into directives
    directives = csp_header.split(';')

    for directive in directives:
        directive = directive.strip()
        parts = directive.split()

        if len(parts) < 2:
            continue

        directive_name = parts[0]

        if directive_name in url_directives:
            for value in parts[1:]:
                # Skip CSP keywords
                if value in ["'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'",
                             "'strict-dynamic'", "'report-sample'", "*", "data:", "blob:"]:
                    continue

                # Extract domains from URLs
                if value.startswith('http://') or value.startswith('https://'):
                    parsed = urlparse(value)
                    if parsed.netloc:
                        domains.add(parsed.netloc)
                elif value.startswith('*.'):
                    # Wildcard subdomain
                    domains.add(value[2:])
                elif '.' in value and not value.startswith("'"):
                    # Likely a domain
                    domains.add(value)

    return list(domains)


def parse_cors_header(cors_header):
    """
    Parse Access-Control-Allow-Origin header
    Returns the origin domain if not wildcard
    """
    if cors_header and cors_header != '*':
        parsed = urlparse(cors_header)
        if parsed.netloc:
            return parsed.netloc
        return cors_header
    return None


def extract_http2_info(requestobject):
    """
    Extract HTTP/2 specific information from response
    """
    http2_info = {}

    # Check HTTP version
    if hasattr(requestobject, 'raw') and hasattr(requestobject.raw, 'version'):
        version = requestobject.raw.version
        if version == 20:
            http2_info['version'] = 'HTTP/2'
        elif version == 11:
            http2_info['version'] = 'HTTP/1.1'
        elif version == 10:
            http2_info['version'] = 'HTTP/1.0'

    # Server push detection (if any link headers with rel=preload)
    if 'link' in requestobject.headers:
        link_header = requestobject.headers['link']
        if 'rel=preload' in link_header or 'rel="preload"' in link_header:
            http2_info['server_push'] = True
            logger.info("HTTP/2 Server Push detected via Link header")

    return http2_info


def analyze_security_headers(requestobject):
    """
    Analyze security-related headers that might reveal backend info
    """
    findings = {}

    security_headers = {
        'strict-transport-security': 'HSTS',
        'x-frame-options': 'Frame Options',
        'x-content-type-options': 'Content Type Options',
        'x-xss-protection': 'XSS Protection',
        'referrer-policy': 'Referrer Policy',
        'permissions-policy': 'Permissions Policy',
        'feature-policy': 'Feature Policy',
        'expect-ct': 'Certificate Transparency',
        'content-security-policy-report-only': 'CSP Report Only',
        'nel': 'Network Error Logging',
        'report-to': 'Reporting API'
    }

    for header, description in security_headers.items():
        if header in requestobject.headers:
            value = requestobject.headers[header]
            findings[header] = value
            logger.info(f"Security header found: {description} = {value}")

            # Extract reporting endpoints which might reveal backend
            if header in ['content-security-policy-report-only', 'report-to', 'nel']:
                # Look for URLs in reporting headers
                urls = re.findall(r'https?://[^\s\'">;]+', value)
                if urls:
                    logger.info(f"Reporting endpoints found in {header}: {urls}")
                    findings[f'{header}_endpoints'] = urls

    return findings


def main(requestobject, doshodan=True, docensys=True, dozoome=True, dofofa=True):
    """
    Process HTTP headers from a request
    """
    interesting_headers = []
    findings = {
        'interesting_headers': [],
        'csp_domains': [],
        'cors_origin': None,
        'http2_info': {},
        'security_headers': {}
    }

    for header in requestobject.headers:
        if header.lower() in ['etag', 'server']:
            interesting_headers.append(header.lower())
            logger.info(f"Found interesting header: {header}")

    findings['interesting_headers'] = interesting_headers

    # Analyze CSP header
    if 'content-security-policy' in requestobject.headers:
        csp = requestobject.headers['content-security-policy']
        logger.info("Content-Security-Policy header found, parsing for domains...")
        domains = parse_csp_header(csp)

        if domains:
            logger.info(f"CSP domains found: {domains}")
            findings['csp_domains'] = domains

            # Query each unique domain
            for domain in domains:
                logger.info(f"Querying intelligence platforms for CSP domain: {domain}")
                if doshodan:
                    query_shodan(f'hostname:"{domain}"')
                if docensys:
                    query_censys(f'host.dns.names="{domain}"')
                if dozoome:
                    query_zoomeye(f'hostname:"{domain}"')

    # Analyze CORS header
    if 'access-control-allow-origin' in requestobject.headers:
        cors_origin = parse_cors_header(requestobject.headers['access-control-allow-origin'])
        if cors_origin:
            logger.info(f"CORS origin found: {cors_origin}")
            findings['cors_origin'] = cors_origin

            # Query the CORS origin
            if doshodan:
                query_shodan(f'hostname:"{cors_origin}"')
            if docensys:
                query_censys(f'host.dns.names="{cors_origin}"')
            if dozoome:
                query_zoomeye(f'hostname:"{cors_origin}"')

    # Extract HTTP/2 info
    http2_info = extract_http2_info(requestobject)
    if http2_info:
        findings['http2_info'] = http2_info
        logger.info(f"HTTP protocol info: {http2_info}")

    # Analyze security headers
    security_findings = analyze_security_headers(requestobject)
    if security_findings:
        findings['security_headers'] = security_findings

    # Original etag processing
    if 'etag' in interesting_headers:
        etag = requestobject.headers['etag']
        if doshodan:
            query_shodan(f'http.headers.etag:"{etag}"')
        if docensys:
            query_censys(f'host.services: (http.response.headers.key="etag" and http.response.headers.value.headers="{etag}")')
        if dozoome:
            query_zoomeye(f'header.etag:"{etag}"')
        if dofofa:
            query_fofa(f'header.etag="{etag}"')

    # Original server processing
    if 'server' in interesting_headers:
        server = requestobject.headers['server']
        if doshodan:
            query_shodan(f'http.headers.server:"{server}"')
        if docensys:
            query_censys(f'host.services: (http.response.headers.key="server" and http.response.headers.value.headers="{server}")')
        if dozoome:
            query_zoomeye(f'header.server:"{server}"')
        if dofofa:
            query_fofa(f'header.server="{server}"')

    return findings
