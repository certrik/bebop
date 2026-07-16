#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import json
import base64
import logging
import requests
from censys_platform import SDK
import shodan

from app import correlate

log = logging.getLogger(__name__)

FOFA_API_KEY = os.getenv('FOFA_API_KEY', None)
FOFA_API_MAIL = os.getenv('FOFA_API_MAIL', None)
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', None)
URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY', None)
MODAT_API_KEY = os.getenv('MODAT_API_KEY', None)
ZOOMEYE_API_KEY = os.getenv('ZOOMEYE_API_KEY', None)
VALIDIN_API_KEY = os.getenv('VALIDIN_API_KEY', None)
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', None)
SECURITYTRAILS_API_KEY = os.getenv('SECURITYTRAILS_API_KEY', None)

VALIDIN_BASE = 'https://app.validin.com'
# The legacy Search API (api_id/api_secret against search.censys.io) has been
# retired. The Censys Platform authenticates with a personal access token
# scoped to an organization id.
CENSYS_PERSONAL_ACCESS_TOKEN = os.getenv('CENSYS_PERSONAL_ACCESS_TOKEN', None)
CENSYS_ORGANIZATION_ID = os.getenv('CENSYS_ORGANIZATION_ID', None)

if SHODAN_API_KEY:
    shodan_api = shodan.Shodan(SHODAN_API_KEY)

def query_zoomeye(squery):
    '''
    Query ZoomEye API for the given search query.
    '''
    findings = []
    if not ZOOMEYE_API_KEY:
        log.warning("zoomeye: without an api key, queries are skipped")
        return findings
    if not squery:
        log.error("zoomeye: no query provided")
        return findings
    log.debug('zoomeye: querying %s', squery)

    headers = {
        'API-KEY': ZOOMEYE_API_KEY,
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'
    }

    # The legacy GET /host/search endpoint has been retired. ZoomEye v2 expects
    # a POST to /v2/search with the dork base64-encoded in the qbase64 field.
    payload = {
        'qbase64': base64.b64encode(squery.encode('utf-8')).decode('utf-8'),
        'page': 1,
        'pagesize': 20,
    }

    try:
        results = requests.post('https://api.zoomeye.ai/v2/search',
                                json=payload,
                                headers=headers,
                                timeout=10)
        results.raise_for_status()
    except requests.exceptions.HTTPError as e:
        log.error('zoomeye: HTTP error: %s', e)
        if e.response is not None:
            log.error('Response status code: %s', e.response.status_code)
            log.error('Response content: %s', e.response.text)
        return findings
    except requests.exceptions.RequestException as e:
        log.error('zoomeye: Request exception: %s', e)
        return findings

    results_data = results.json()
    if results_data.get('code') != 60000:
        log.error('zoomeye: api error: %s - %s',
                  results_data.get('code'), results_data.get('message'))
        return findings
    total_results = results_data.get('total', 0)
    log.info('zoomeye: found %s results for %s', total_results, squery)

    if total_results <= 20:
        for result in results_data.get('data', []):
            findings.append(result)
            log.info('zoomeye: found %s', result.get('ip'))
            log.debug('zoomeye: %s', result.get('banner'))
            correlate.add_candidate(result.get('ip'), 'zoomeye', squery)
    else:
        log.warning('zoomeye: more than 20 results found. Skipping query as it is not deemed rare.')
    return findings

def query_censys(squery):
    findings = []
    if not (CENSYS_PERSONAL_ACCESS_TOKEN and CENSYS_ORGANIZATION_ID):
        log.warning("censys: without a personal access token and organization id queries are skipped")
        return findings
    if not squery:
        log.error("censys: no query provided")
        return findings
    try:
        log.debug('censys: querying %s', squery)
        # Censys Platform: POST /v3/global/search/query via the SDK. Queries use
        # CenQL (host.* field paths) rather than the legacy Search syntax.
        with SDK(personal_access_token=CENSYS_PERSONAL_ACCESS_TOKEN,
                 organization_id=CENSYS_ORGANIZATION_ID) as sdk:
            response = sdk.global_data.search(search_query_input_body={
                'query': squery,
                'fields': ['host.ip'],
                'page_size': 30,
            })
        # Response envelope: response.result.result.hits
        result = getattr(response, 'result', None)
        inner = getattr(result, 'result', None)
        hits = getattr(inner, 'hits', None) or []
        total_results = len(hits)
        log.info('censys: found %s results for %s', total_results, squery)
        if total_results == 0:
            return findings
        if total_results <= 20:
            for hit in hits:
                findings.append(hit)
                log.info('censys: found %s', hit)
                _ip = hit.get('ip') if isinstance(hit, dict) else getattr(hit, 'ip', None)
                correlate.add_candidate(_ip, 'censys', squery)
        else:
            log.warning('censys: more than 20 results found. skipping query as it is not deemed rare.')
    except Exception as e:
        log.error('censys: api error: %s', e)
    return findings

def query_shodan(squery):
    findings = []
    if not SHODAN_API_KEY:
        log.warning("shodan: without an api key queries are skipped")
        return findings
    if not squery:
        log.error("shodan: no query provided")
        return findings
    try:
        log.debug('shodan: querying %s', squery)
        results = shodan_api.search(squery)
        total_results = results['total']
        log.info('shodan: found %s results for %s', total_results, squery)
        if total_results <= 20:
            for result in results['matches']:
                findings.append(result)
                log.info('shodan: found %s', result['ip_str'])
                log.debug('shodan: %s', result['data'])
                correlate.add_candidate(result.get('ip_str'), 'shodan', squery)
        else:
            log.warning('shodan: more than 20 results found. skipping query as it is not deemed rare.')
    except shodan.APIError as sae:
        log.error('shodan: api error: %s', sae)
    return findings

def query_fofa(squery):
    '''
    https://en.fofa.info/api
    '''
    findings = []
    if not FOFA_API_KEY or not FOFA_API_MAIL:
        log.warning("fofa: without an api key and email queries are skipped")
        return findings
    if not squery:
        log.error("fofa: no query provided")
        return findings
    query64 = base64.b64encode(squery.encode('utf-8'))
    log.debug('fofa: querying %s (%s)', squery, query64)
    try:
        results = requests.get('https://fofa.info/api/v1/search/all',
                               params={
                                   'qbase64': query64,
                                   'fields': 'ip,port,banner',
                                   'size': 20,
                                   'page': 1,
                                   'key': FOFA_API_KEY,
                                   'email': FOFA_API_MAIL
                                }
        )
        results.raise_for_status()
    except requests.exceptions.RequestException as e:
        log.error('fofa: api error: %s', e)
        return findings
    results_data = results.json()
    if 'errmsg' in results_data:
        if '[820019]' in results_data['errmsg']:
            log.error('fofa: icon_hash queries are not supported on basic plans.')
            return findings
        log.error('fofa: unknown api error: %s', results_data['errmsg'])
        return findings
    total_results = results_data['size']
    log.info('fofa: found %s results for %s', total_results, squery)
    if total_results <= 20:
        for result in results_data['results']:
            findings.append(result)
            log.info('fofa: found ' + str(result[0]))
            correlate.add_candidate(result[0], 'fofa', squery)
    else:
        log.warning('fofa: more than 20 results found. skipping query as it is not deemed rare.')
    return findings

def query_modat(squery):
    '''
    Query the Modat Magnify service-level search API.
    https://api.magnify.modat.io/docs

    Queries use the Modat query language (e.g. `web.title ~ "Login"`,
    `tls.fingerprint_sha256:<hash>`).
    '''
    findings = []
    if not MODAT_API_KEY:
        log.warning("modat: without an api key queries are skipped")
        return findings
    if not squery:
        log.error("modat: no query provided")
        return findings
    log.debug('modat: querying %s', squery)

    headers = {
        'Authorization': f'Bearer {MODAT_API_KEY}',
        'Content-Type': 'application/json',
    }
    # page_size accepts 10-100; 20 lets us confirm the rarity threshold in one page.
    payload = {'query': squery, 'page': 1, 'page_size': 20}

    try:
        results = requests.post('https://api.magnify.modat.io/service/search/v1',
                                json=payload,
                                headers=headers,
                                timeout=10)
        results.raise_for_status()
    except requests.exceptions.HTTPError as e:
        log.error('modat: HTTP error: %s', e)
        if e.response is not None:
            log.error('Response status code: %s', e.response.status_code)
            log.error('Response content: %s', e.response.text)
        return findings
    except requests.exceptions.RequestException as e:
        log.error('modat: request exception: %s', e)
        return findings

    results_data = results.json()
    total_results = results_data.get('total_records', 0)
    log.info('modat: found %s results for %s', total_results, squery)
    if total_results <= 20:
        for result in results_data.get('page', []):
            findings.append(result)
            log.info('modat: found %s', result.get('ip'))
            correlate.add_candidate(result.get('ip'), 'modat', squery)
    else:
        log.warning('modat: more than 20 results found. skipping query as it is not deemed rare.')
    return findings

def query_shodanindernetdb(ip):
    '''
    https://internetdb.shodan.io
    '''
    results = requests.get('https://internetdb.shodan.io/' + ip)
    if results.status_code != 200:
        log.error('shodanindernetdb: api error: %s - %s', results.status_code, results.text)
        return None
    results = results.json()
    if not results['ports']:
        log.warning('shodanindernetdb: no ports found')
    else:
        log.info('shodanindernetdb: found %s', results)

def query_resolutions_securitytrails(ip_address):
    if not SECURITYTRAILS_API_KEY:
        log.warning("securitytrails: without an api key queries are skipped")
        return set()
    url = f"https://api.securitytrails.com/v1/ips/nearby/{ip_address}"
    headers = {"apikey": SECURITYTRAILS_API_KEY}
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code != 200:
        logging.error(f"unhandled error: {response.status_code} - {response.text}")
        return set()
    data = response.json()
    hostnames = set()
    for block in data.get("blocks", []):
        for hostname in block.get("hostnames", []):
            hostnames.add(hostname)
    logging.info(f"found {len(hostnames)} hostnames on SecurityTrails")
    return hostnames

def query_resolutions_virustotal(ip_address):
    if not VIRUSTOTAL_API_KEY:
        log.warning("virustotal: without an api key queries are skipped")
        return set()
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/resolutions"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code != 200:
        logging.error(f"unhandled error: {response.status_code} - {response.text}")
        return set()
    data = response.json()
    hostnames = set()
    for item in data.get("data", []):
        if 'attributes' in item and 'host_name' in item['attributes']:
            hostnames.add(item['attributes']['host_name'])
    logging.info(f"found {len(hostnames)} hostnames on VirusTotal")
    return hostnames

def query_resolutions_urlscan(ip_address):
    if not URLSCAN_API_KEY:
        log.warning("urlscan: without an api key queries are skipped")
        return set()
    search_url = f'https://urlscan.io/api/v1/search/?q=ip:"{ip_address}"'
    headers = {
        'API-Key': URLSCAN_API_KEY,
        'Content-Type': 'application/json'
    }
    response = requests.get(search_url, headers=headers, timeout=10)
    if response.status_code != 200:
        logging.error(f"unhandled error: {response.status_code} - {response.text}")
        return set()
    data = response.json()
    hostnames = set()
    for item in data.get('results', []):
        if 'task' in item and 'domain' in item['task']:
            hostnames.add(item['task']['domain'])
    logging.info(f"found {len(hostnames)} hostnames on urlscan.io")
    return hostnames

# --- Validin (https://app.validin.com) -----------------------------------
# Scoped to the single-indicator endpoints covered by the Pro tier's
# "Expanded" API access: reverse passive-DNS history and host-response hash
# pivots. Enterprise-only surfaces (bulk, live scan, CIDR ranges, threat/
# project APIs) are intentionally not used.

def _validin_get(path):
    '''GET a Validin API path with Bearer auth; returns parsed JSON or None.'''
    try:
        response = requests.get(
            VALIDIN_BASE + path,
            headers={'Authorization': 'BEARER ' + VALIDIN_API_KEY},
            timeout=15,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        log.error('validin: api error: %s', e)
        return None
    return response.json()


def _validin_is_domain(token, exclude=None):
    '''Loose check: a token that looks like a hostname rather than an IP.'''
    if not token or token == exclude:
        return False
    if '.' not in token:
        return False
    # reject bare IPv4 / IPv6
    if all(part.isdigit() for part in token.split('.')):
        return False
    if ':' in token:
        return False
    return any(c.isalpha() for c in token)


def query_resolutions_validin(ip_address):
    '''
    Historical passive-DNS reverse lookup: every hostname Validin has ever seen
    resolving to this IP. Unlike current-only sources, this surfaces domains
    that pointed at the origin in the past and were later moved away.
    '''
    if not VALIDIN_API_KEY:
        log.warning("validin: without an api key queries are skipped")
        return set()
    data = _validin_get('/api/axon/ip/dns/history/' + ip_address)
    if not data:
        return set()
    hostnames = set()
    for _rtype, records in (data.get('records') or {}).items():
        for rec in records:
            for token in (rec.get('key'), rec.get('value')):
                if _validin_is_domain(token, exclude=ip_address):
                    if token not in hostnames:
                        log.info('validin: %s seen on %s (first=%s last=%s)',
                                 token, ip_address, rec.get('first_seen'), rec.get('last_seen'))
                    hostnames.add(token)
    log.info('validin: found %s historical hostnames for %s', len(hostnames), ip_address)
    return hostnames


def query_validin_pivot(hash_value):
    '''
    Pivot a host-response fingerprint (favicon md5, HTTP body sha1, certificate
    sha1, or JARM) to the domains/IPs Validin has seen sharing it. A rare
    fingerprint shared with a clearnet host is a strong deanonymisation lead.
    '''
    findings = []
    if not VALIDIN_API_KEY:
        log.warning("validin: without an api key queries are skipped")
        return findings
    if not hash_value:
        log.error("validin: no hash provided")
        return findings
    data = _validin_get('/api/axon/hash/pivots/' + str(hash_value))
    if not data:
        return findings
    for _rtype, records in (data.get('records') or {}).items():
        for rec in records:
            findings.append(rec)
    total = len(findings)
    log.info('validin: found %s pivot records for hash %s', total, hash_value)
    if total <= 20:
        for rec in findings:
            log.info('validin: hash %s -> %s / %s (last=%s)',
                     hash_value, rec.get('value'), rec.get('key'), rec.get('last_seen'))
            for token in (rec.get('value'), rec.get('key')):
                if _validin_is_domain(token, exclude=str(hash_value)):
                    correlate.add_candidate(token, 'validin', 'validin:pivot')
    else:
        log.warning('validin: more than 20 pivots for %s - not deemed rare, skipping detail', hash_value)
    return findings
