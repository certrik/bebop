#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Content-leak & attribution scanner.

Hidden services are most often deanonymised through operator mistakes that leak
directly in the page they serve, rather than through the Tor network itself.
This module hunts for those leaks:

  * clearnet resources the page loads (script/img/link/iframe/form ...), which
    make the browser fetch from the operator's real infrastructure
  * Onion-Location / rel=canonical / rel=alternate pointers to a clearnet twin
  * PGP public keys and contact e-mails (operator attribution)
  * a hash of the response body, pivoted on the scan engines the same way the
    favicon hash is - operators routinely serve byte-identical pages on the
    onion and on the exposed clearnet origin
'''
import re
import logging
import mmh3
import hashlib
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from app.subprocessors import query_shodan, query_zoomeye, query_validin_pivot

log = logging.getLogger(__name__)

# Elements whose URL attribute causes the browser to *fetch* from that host.
# A clearnet host here is a far stronger signal than an ordinary outbound <a>.
RESOURCE_ELEMENTS = {
    'script': 'src',
    'link': 'href',
    'img': 'src',
    'iframe': 'src',
    'form': 'action',
    'video': 'src',
    'audio': 'src',
    'source': 'src',
    'embed': 'src',
    'object': 'data',
    'track': 'src',
}

EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
CSS_URL_RE = re.compile(r'url\(\s*[\'"]?(https?://[^\'")\s]+)', re.IGNORECASE)
ABS_URL_RE = re.compile(r'https?://[^\s\'"<>)]+', re.IGNORECASE)
PGP_BLOCK_RE = re.compile(
    r'-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----',
    re.DOTALL,
)


def _host_of(url):
    try:
        return urlparse(url).hostname or ''
    except ValueError:
        return ''


def _is_clearnet_host(host, self_host):
    '''A host worth reporting: a real clearnet name that is not the onion itself.'''
    if not host:
        return False
    host = host.lower()
    if host == (self_host or '').lower():
        return False
    if host.endswith('.onion'):
        return False
    # ignore bare IPs of the local/loopback kind and obvious non-hosts
    if host in ('localhost',):
        return False
    return '.' in host


def extract_clearnet_resources(html, self_host):
    '''
    Return clearnet hosts the page actively loads resources from, with the
    element/attribute that leaked them. These are the primary deanon signal.
    '''
    soup = BeautifulSoup(html, 'html.parser')
    leaks = []
    for tag, attr in RESOURCE_ELEMENTS.items():
        for el in soup.find_all(tag):
            url = el.get(attr)
            if not url:
                continue
            if url.startswith('//'):
                url = 'https:' + url
            if not url.lower().startswith(('http://', 'https://')):
                continue
            host = _host_of(url)
            if _is_clearnet_host(host, self_host):
                leaks.append({'host': host, 'url': url, 'element': tag, 'attribute': attr})

    # CSS url(...) references (inline <style> and style="" attributes)
    for match in CSS_URL_RE.findall(html):
        host = _host_of(match)
        if _is_clearnet_host(host, self_host):
            leaks.append({'host': host, 'url': match, 'element': 'css', 'attribute': 'url()'})

    return leaks


def extract_outbound_links(html, self_host):
    '''Anchor hrefs to clearnet hosts - weaker signal, reported separately.'''
    soup = BeautifulSoup(html, 'html.parser')
    hosts = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith('//'):
            href = 'https:' + href
        host = _host_of(href)
        if _is_clearnet_host(host, self_host):
            hosts.add(host)
    return sorted(hosts)


def extract_onion_location(requestobject, html):
    '''
    The Onion-Location response header and rel=canonical / rel=alternate links
    frequently point straight at the clearnet twin of the service.
    '''
    findings = {}
    headers = getattr(requestobject, 'headers', {}) or {}
    for key in headers:
        if key.lower() == 'onion-location':
            findings['onion_location'] = headers[key]

    soup = BeautifulSoup(html, 'html.parser')
    canonicals = []
    for link in soup.find_all('link', href=True):
        rel = ' '.join(link.get('rel', [])).lower() if link.get('rel') else ''
        if rel in ('canonical', 'alternate'):
            canonicals.append(link['href'])
    if canonicals:
        findings['canonical_links'] = canonicals
    return findings


def extract_pgp_keys(text):
    '''Return PGP public key blocks with a short fingerprint-style identifier.'''
    keys = []
    for block in PGP_BLOCK_RE.findall(text):
        # a stable id for correlation without a full OpenPGP parse
        key_id = hashlib.sha256(block.encode('utf-8', 'ignore')).hexdigest()[:16]
        keys.append({'id': key_id, 'block': block})
    return keys


def extract_emails(html):
    soup = BeautifulSoup(html, 'html.parser')
    emails = set()
    for a in soup.find_all('a', href=True):
        if a['href'].lower().startswith('mailto:'):
            addr = a['href'][7:].split('?')[0].strip()
            if addr:
                emails.add(addr.lower())
    for match in EMAIL_RE.findall(html):
        emails.add(match.lower())
    return sorted(emails)


def compute_body_hash(content):
    '''
    Body hashes for cross-engine pivoting:
      * mmh3  - Shodan http.html_hash / Modat web.body_mmh3
      * md5   - ZoomEye body_hash
      * sha1  - Validin HTTP body hash
      * sha256 - correlation / de-dup
    '''
    if isinstance(content, str):
        content = content.encode('utf-8', 'ignore')
    return {
        'mmh3': mmh3.hash(content),
        'md5': hashlib.md5(content).hexdigest(),
        'sha1': hashlib.sha1(content).hexdigest(),
        'sha256': hashlib.sha256(content).hexdigest(),
    }


def main(requestobject, doshodan=True, docensys=True, dozoome=True, dofofa=True, domodat=True, dovalidin=True):
    html = requestobject.text
    self_host = _host_of(requestobject.url)
    findings = {
        'clearnet_resources': [],
        'outbound_hosts': [],
        'onion_location': {},
        'pgp_keys': [],
        'emails': [],
        'body_hash': None,
    }

    findings['clearnet_resources'] = extract_clearnet_resources(html, self_host)
    if findings['clearnet_resources']:
        hosts = sorted({leak['host'] for leak in findings['clearnet_resources']})
        log.warning('contentleak: page loads clearnet resources from: %s', ', '.join(hosts))
        for leak in findings['clearnet_resources']:
            log.info('contentleak: %s leaks %s via <%s %s>',
                     self_host or 'target', leak['host'], leak['element'], leak['attribute'])

    findings['outbound_hosts'] = extract_outbound_links(html, self_host)
    if findings['outbound_hosts']:
        log.info('contentleak: outbound clearnet links to: %s', ', '.join(findings['outbound_hosts']))

    findings['onion_location'] = extract_onion_location(requestobject, html)
    if findings['onion_location'].get('onion_location'):
        log.warning('contentleak: Onion-Location header points to %s',
                    findings['onion_location']['onion_location'])
    for canon in findings['onion_location'].get('canonical_links', []):
        log.info('contentleak: canonical/alternate link: %s', canon)

    findings['pgp_keys'] = extract_pgp_keys(html)
    for key in findings['pgp_keys']:
        log.info('contentleak: PGP public key found (id %s)', key['id'])

    findings['emails'] = extract_emails(html)
    for email in findings['emails']:
        log.info('contentleak: contact e-mail found: %s', email)

    # Body-content pivot: operators often serve identical pages on onion + clearnet
    body_hash = compute_body_hash(requestobject.content)
    findings['body_hash'] = body_hash
    log.info('contentleak: body hash mmh3=%s md5=%s sha1=%s sha256=%s',
             body_hash['mmh3'], body_hash['md5'], body_hash['sha1'], body_hash['sha256'])
    # Shodan indexes the mmh3 of the HTML body (http.html_hash); ZoomEye indexes
    # its md5 (body_hash); Validin pivots on the sha1. (Modat rejects a body-hash
    # field - web.body_mmh3 is unsupported - and FOFA/Censys have no equivalent.)
    if doshodan:
        query_shodan('http.html_hash:' + str(body_hash['mmh3']))
    if dozoome:
        query_zoomeye('body_hash:' + body_hash['md5'])
    if dovalidin:
        query_validin_pivot(body_hash['sha1'])

    return findings
