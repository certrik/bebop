#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Correlation & confirmation layer.

Every pivot in bebop surfaces candidate clearnet endpoints in isolation and
logs them. This module fuses them into a single verdict:

  1. Collect each (selector -> candidate) edge as the pivots run.
  2. Rank candidates by how many *independent selector categories* corroborate
     them - a host matched by cert + JARM + favicon + body-hash is far stronger
     than one matched by a single common favicon.
  3. Confirm the top candidates by fetching each over clearnet and diffing the
     response against the onion baseline (byte-identical body = near-certain
     deanonymisation).

The result is a ranked, confirmed candidate-origin list instead of a pile of
independent hits.
'''
import logging
import hashlib
import mmh3

log = logging.getLogger(__name__)

# Map a pivot's selector string to a category, so the same underlying asset
# pivoted across several engines counts as ONE independent line of evidence per
# category rather than one per engine.
_CATEGORY_RULES = [
    ('favicon', ('favicon', 'iconhash', 'icon_hash')),
    ('jarm', ('jarm',)),
    ('cert_fp', ('fingerprint_sha256', 'fingerprint.sha256', 'cert.fingerprint',
                 'leaf_data.fingerprint', 'ssl.fingerprint')),
    ('cert_serial', ('cert.serial', 'serial_number', 'cert=')),
    ('title', ('title',)),
    ('body', ('html_hash', 'body_mmh3', 'body_hash')),
    ('hostname', ('hostname', 'dns.names', 'fqdns', 'dns_names')),
    ('header', ('etag', 'header.server', 'headers.server', 'header.etag')),
    ('pdns', ('pdns', 'resolution')),
]

_candidates = {}


def reset():
    '''Clear collected candidates (call once at the start of a scan / test).'''
    _candidates.clear()


def _classify(selector):
    s = (selector or '').lower()
    for category, needles in _CATEGORY_RULES:
        for n in needles:
            if n in s:
                return category
    return 'other'


def _normalize(candidate):
    if candidate is None:
        return None
    c = str(candidate).strip().lower().rstrip('.')
    # strip obvious non-hosts
    if not c or c in ('none', 'null', '0.0.0.0'):
        return None
    return c


def add_candidate(candidate, source, selector):
    '''Register that `source` linked `candidate` to the target via `selector`.'''
    try:
        c = _normalize(candidate)
        if not c:
            return
        entry = _candidates.setdefault(
            c, {'sources': set(), 'categories': set(), 'selectors': set()})
        entry['sources'].add(source)
        entry['categories'].add(_classify(selector))
        entry['selectors'].add(selector)
    except Exception as e:  # correlation must never break a scan
        log.debug('correlate: failed to add candidate %s: %s', candidate, e)


def _score(entry):
    # independent selector categories dominate; engine agreement breaks ties
    return (len(entry['categories']), len(entry['sources']))


def ranked_candidates():
    return sorted(_candidates.items(), key=lambda kv: _score(kv[1]), reverse=True)


def _extract_title(html):
    try:
        from bs4 import BeautifulSoup
        tag = BeautifulSoup(html, 'html.parser').find('title')
        return tag.text.strip() if tag and tag.text else None
    except Exception:
        return None


def _fingerprint_response(resp):
    content = resp.content or b''
    server = None
    try:
        server = (resp.headers.get('server') or '').strip() or None
    except Exception:
        pass
    return {
        'body_sha256': hashlib.sha256(content).hexdigest(),
        'body_mmh3': mmh3.hash(content),
        'title': _extract_title(resp.text),
        'server': server,
    }


def confirm_candidate(candidate, baseline, fetch_fn):
    '''
    Fetch a candidate over clearnet and diff it against the onion baseline.

    Returns a dict with `verdict` in CONFIRMED / LIKELY / WEAK / NO_MATCH /
    UNREACHABLE and the list of baseline fingerprints that matched.
    '''
    result = {'candidate': candidate, 'url': None, 'reachable': False,
              'matches': [], 'verdict': 'UNREACHABLE'}
    resp = None
    for scheme in ('https', 'http'):
        url = f'{scheme}://{candidate}/'
        try:
            resp = fetch_fn(url)
        except Exception as e:
            log.debug('correlate: fetch failed for %s: %s', url, e)
            resp = None
        if resp is not None:
            result['url'] = url
            result['reachable'] = True
            break
    if not result['reachable']:
        return result

    fp = _fingerprint_response(resp)
    matches = []
    if baseline.get('body_sha256') and fp['body_sha256'] == baseline['body_sha256']:
        matches.append('body_sha256')
    elif baseline.get('body_mmh3') is not None and fp['body_mmh3'] == baseline['body_mmh3']:
        matches.append('body_mmh3')
    if baseline.get('title') and fp['title'] and fp['title'] == baseline['title']:
        matches.append('title')
    if baseline.get('server') and fp['server'] and fp['server'] == baseline['server']:
        matches.append('server')
    result['matches'] = matches

    if 'body_sha256' in matches or 'body_mmh3' in matches:
        result['verdict'] = 'CONFIRMED'      # byte-identical page served on clearnet
    elif 'title' in matches and 'server' in matches:
        result['verdict'] = 'LIKELY'
    elif matches:
        result['verdict'] = 'WEAK'
    else:
        result['verdict'] = 'NO_MATCH'
    return result


_VERDICT_ORDER = {'CONFIRMED': 0, 'LIKELY': 1, 'WEAK': 2, 'NO_MATCH': 3, 'UNREACHABLE': 4}


def correlate_and_confirm(baseline, fetch_fn, top_n=10):
    '''
    Rank collected candidates, confirm the top `top_n` against the baseline, and
    return them ordered by verdict then corroboration strength.
    '''
    ranked = ranked_candidates()
    if not ranked:
        log.info('correlate: no candidate origins collected')
        return []
    log.info('correlate: %s candidate origin(s) collected, confirming top %s',
             len(ranked), min(top_n, len(ranked)))

    results = []
    for candidate, entry in ranked[:top_n]:
        conf = confirm_candidate(candidate, baseline, fetch_fn)
        cats, srcs = _score(entry)
        results.append({
            'candidate': candidate,
            'categories': sorted(entry['categories']),
            'category_count': cats,
            'sources': sorted(entry['sources']),
            'confirmation': conf,
        })
        log.warning('correlate: candidate %s [%s selector categories: %s] via %s -> %s',
                    candidate, cats, ','.join(sorted(entry['categories'])),
                    ','.join(sorted(entry['sources'])), conf['verdict'])

    results.sort(key=lambda r: (_VERDICT_ORDER.get(r['confirmation']['verdict'], 9),
                                -r['category_count']))
    confirmed = [r for r in results if r['confirmation']['verdict'] == 'CONFIRMED']
    if confirmed:
        log.warning('correlate: %s candidate(s) CONFIRMED as clearnet origin: %s',
                    len(confirmed), ', '.join(r['candidate'] for r in confirmed))
    return results
