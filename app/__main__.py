#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import logging
import asyncio
import argparse
import datetime
import time

from app.getpage import main as getpage_main
from app.headers import main as headers_main
from app.favicon import main as favicon_main
from app.pagespider import main as pagespider_main
from app.title import main as title_main
from app.portscan import main as portscan_main
from app.configcheck import main as configcheck_main
from app.opendir import main as opendir_main
from app.getcert import main as getcert_main
from app.cliart import prints as cliart_main
from app.cryptocurrency import main as cryptocurrency_main
from app.finddomains import main as finddomains_main
from app.analytics import main as analytics_main
from app.contentleak import main as contentleak_main
from app.robotsmap import main as robotsmap_main
from app import correlate
from app import oob
from app.tlsfingerprint import main as tlsfingerprint_main
from app.htmlreport import generate_html_report, save_html_report
from app.utilities import preflight, getfqdn, getbaseurl, validurl, getport, refang_url


def main():
    # Start timing
    start_time = time.time()

    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='target address')
    parser.add_argument('--loglevel',
                        help='set logging level',
                        default='INFO',
                        choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'])
    parser.add_argument('--clearnet',
                        help='route traffic over clearnet (no tor)',
                        action='store_true',
                        default=False)
    parser.add_argument('--useragent',
                        help='set user-agent',
                        default='Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0')
    parser.add_argument('--html-report',
                        help='generate HTML report (file path)',
                        default=None)
    # --- out-of-band callback deanonymisation (ACTIVE / opt-in) ---
    # WARNING: this induces the target to connect back to your listener, which
    # exposes your callback infrastructure to the target operator. The Tor
    # anonymity on the probe leg does NOT cover the callback leg. See app/oob.py.
    # Every option can also be supplied via BEBOP_OOB_* env vars (for CI).
    parser.add_argument('--oob-callback',
                        help='ACTIVE deanon: callback host you control (e.g. an '
                             'interactsh/collaborator host). Enables OOB. See '
                             'OPSEC notes in app/oob.py - this can expose YOU.',
                        default=None)
    parser.add_argument('--oob-poll-url',
                        help='listener poll URL template ({TOKEN} substituted) '
                             'returning JSON interactions',
                        default=None)
    parser.add_argument('--oob-scheme', help='callback scheme (default http)', default=None)
    parser.add_argument('--oob-inject', action='append',
                        help='SSRF URL template with {CALLBACK} (repeatable)', default=None)
    parser.add_argument('--oob-wait', help='seconds to wait for a callback (default 25)', default=None)
    parser.add_argument('--oob-path-style', action='store_true',
                        help='use host/token instead of token.host callbacks', default=False)
    args = parser.parse_args()

    logging.basicConfig(
        # force=True so bebop owns the root logger even if an imported library
        # (e.g. pyjarm) installed a handler at import time, which would otherwise
        # make this a no-op and silently suppress INFO/DEBUG output.
        force=True,
        level=logging.getLevelName(args.loglevel),
        format='%(asctime)-11s %(levelname)-8s %(lineno)d:%(filename)-15s %(funcName)-25s %(message)s',
        datefmt="%I:%M:%S%p",
    )

    if len(sys.argv) == 1:
        print(
        r'''
                __
        _(\    |@@|                        __         __
        (__/\__ \--/ __                    / /_  ___  / /_  ____  ____
            \___|----|  |   __             / __ \/ _ \/ __ \/ __ \/ __ \
                \ }{ /\ )_ / _\           / /_/ /  __/ /_/ / /_/ / /_/ /
                /\__/\ \__O (__          /_.___/\___/_.___/\____/ .___/
            (--/\--)    \__/                                /_/
            _)(  )(_
            `---''---`                 hidden service safari 👀 🧅 💻
        '''
        )

    if os.environ.get('GITHUB_ACTIONS') is None:
        cliart_main()

    # Refang URL if it's defanged (hxxp, [.], etc.)
    args.target = refang_url(args.target)

    if args.clearnet is True:
        logging.critical('clearnet routing enabled..')
        torstate = False
    else:
        logging.debug('tor routing enabled..')
        torstate = True
        preflight()

    protocol_assumed = False
    if not validurl(args.target):
        if validurl('http://' + args.target):
            args.target = 'http://' + args.target
            protocol_assumed = True
            logging.warning('no protocol provided, appending (now: %s)', args.target)
        else:
            logging.critical('failed to parse url - ensure a protocol is specified')
            sys.exit(1)
    fqdn = getfqdn(args.target)
    if fqdn.endswith('.onion'):
        if torstate is False:
            logging.critical('you cannot disable tor routing if your target is a .onion service!')
            sys.exit(1)
    url_base = getbaseurl(args.target)
    logging.debug('target: %s url_base: %s fqdn: %s', args.target, url_base, fqdn)

    # Fresh correlation state for this scan; pivots feed candidates into it.
    correlate.reset()

    requestobject = getpage_main(args.target, usetor=torstate)
    if requestobject is None and protocol_assumed and args.target.startswith('http://'):
        # the assumed http:// (port 80) was refused; many services (incl. onions)
        # only serve https, so retry over https before giving up
        https_target = 'https://' + args.target[len('http://'):]
        logging.warning('http retrieval failed, retrying over https: %s', https_target)
        retry = getpage_main(https_target, usetor=torstate)
        if retry is not None:
            args.target = https_target
            url_base = getbaseurl(args.target)
            requestobject = retry
    if requestobject is None:
        logging.error('failed to retrieve page')
        sys.exit(1)
    if requestobject.status_code != 200:
        logging.warning('unexpected response code: %s', requestobject.status_code)
    if args.target.startswith('https'):
        targetport = getport(args.target) or 443
        getcert_data = getcert_main(fqdn, port=targetport)

    title_data = title_main(requestobject)
    header_data = headers_main(requestobject)
    discovered_paths = asyncio.run(configcheck_main(url_base, usetor=torstate))

    # Mine any config leaks for the origin's real addressing and feed them into
    # the correlation layer: a leaked SERVER_ADDR / instance IP is a direct
    # origin candidate, and leaked internal hostnames become extra pivots.
    leaked_public_ips = set()
    leaked_hostnames = set()
    for _p in (discovered_paths or []):
        _ind = _p.get('indicators') or {}
        for _ip in _ind.get('public_ips', []):
            leaked_public_ips.add(_ip)
            correlate.add_candidate(_ip, 'configcheck', f'configcheck:origin_leak:{_p["path"]}')
        for _h in _ind.get('hostnames', []):
            leaked_hostnames.add(_h)
            correlate.add_candidate(_h, 'configcheck', f'configcheck:origin_leak:{_p["path"]}')
    if leaked_public_ips or leaked_hostnames:
        logging.warning('config checks leaked origin indicators - IPs: %s hostnames: %s',
                        sorted(leaked_public_ips), sorted(leaked_hostnames))

    # ACTIVE out-of-band deanon (opt-in). Trigger the callback here so the rest
    # of the scan doubles as the wait window; the listener is polled later. This
    # is intrusive and exposes the researcher's callback host - see app/oob.py.
    oob_config = oob.resolve_config(args)
    oob_state = None
    if oob_config:
        try:
            oob_state = oob.trigger(url_base, oob_config, usetor=torstate)
        except Exception as e:
            logging.error('oob trigger failed (%s) - continuing', e)
    favicon_data = favicon_main(url_base, requestobject, usetor=torstate)
    pagespider_data = pagespider_main(requestobject, usetor=torstate, skip_queryurl=True)
    cryptocurrency_data = cryptocurrency_main(requestobject.text)

    # NEW: Analytics and tracking code extraction
    analytics_data = analytics_main(requestobject)

    # NEW: Content-leak & attribution scan (clearnet resources, Onion-Location,
    # PGP/e-mail, body-hash pivot)
    contentleak_data = contentleak_main(requestobject)

    # NEW: Robots.txt and sitemap analysis
    robotsmap_data = robotsmap_main(url_base, usetor=torstate)

    # NEW: TLS fingerprinting (for HTTPS sites)
    tlsfingerprint_data = None
    if args.target.startswith('https'):
        tlsfingerprint_data = tlsfingerprint_main(fqdn, port=targetport, usetor=torstate)

    # Get the IP address from the request object
    domains_data = []
    if hasattr(requestobject, 'raw') and hasattr(requestobject.raw, 'connection') and hasattr(requestobject.raw.connection, 'sock'):
        ip_address = requestobject.raw.connection.sock.getpeername()[0]
        logging.info(f"IP address: {ip_address}")
        # Use finddomains to discover domains resolving to this IP
        domains_data = finddomains_main(ip_address) or []
        if domains_data:
            logging.info(f"Found {len(domains_data)} domains resolving to {ip_address}")
            for domain in domains_data:
                logging.info(f"Domain: {domain}")
                correlate.add_candidate(domain, 'pdns', 'pdns:resolution')

    for item in pagespider_data['samedomain']:
        itemsource = getpage_main(item)
        if itemsource is not None:
            opendir_main(itemsource)
            cryptocurrency_main(requestobject.text)
    try:
        portscan_data = portscan_main(fqdn, useragent=args.useragent, usetor=torstate)
    except Exception as e:
        logging.error('portscan failed (%s) - continuing without port data', e)
        portscan_data = None

    # NEW: fuse every pivot's candidates and confirm the strongest against the
    # onion baseline by fetching them over clearnet.
    baseline = {
        'title': title_data,
        'server': dict(requestobject.headers).get('Server') or dict(requestobject.headers).get('server'),
        'body_sha256': (contentleak_data.get('body_hash') or {}).get('sha256') if contentleak_data else None,
        'body_mmh3': (contentleak_data.get('body_hash') or {}).get('mmh3') if contentleak_data else None,
        'favicon_md5': (favicon_data or {}).get('md5'),
        'jarm': (tlsfingerprint_data or {}).get('jarm'),
    }
    reverse_resolved = {}
    try:
        deanon_candidates = correlate.correlate_and_confirm(
            baseline, fetch_fn=lambda u: getpage_main(u, usetor=False))
        # Second-order: reverse-resolve candidate IPs (urlscan/VT/SecurityTrails/
        # Validin) into domains, confirm them, and fold them into the ranking.
        reverse_resolved, reverse_records = correlate.reverse_resolve_and_confirm(
            deanon_candidates, finddomains_main, baseline,
            fetch_fn=lambda u: getpage_main(u, usetor=False))
        if reverse_records:
            deanon_candidates = correlate.rank_results(deanon_candidates + reverse_records)
    except Exception as e:
        logging.error('correlation/confirmation failed (%s)', e)
        deanon_candidates = []

    # High-trust shortcut: directly confirm origin IPs leaked by config checks by
    # fetching each over clearnet and diffing against the onion baseline. A
    # byte-identical body served on the leaked IP is a near-certain deanon.
    origin_leaks = []
    for _ip in sorted(leaked_public_ips):
        try:
            verdict = correlate.confirm_candidate(
                _ip, baseline, fetch_fn=lambda u: getpage_main(u, usetor=False))
            origin_leaks.append(verdict)
            if verdict.get('verdict') in ('CONFIRMED', 'LIKELY'):
                logging.warning('origin IP leaked via config check: %s => %s (%s)',
                                _ip, verdict['verdict'], verdict.get('url'))
        except Exception as e:
            logging.debug('origin-leak confirmation failed for %s: %s', _ip, e)

    # Collect any OOB callbacks the target made to the researcher's listener. A
    # recorded source IP is the origin's real clearnet egress - a direct deanon.
    oob_result = None
    if oob_state is not None:
        try:
            oob_result = oob.poll(oob_config, oob_state)
            for _ip in oob_result.get('source_ips', []):
                correlate.add_candidate(_ip, 'oob', f'oob:callback:{oob_state["token"]}')
                try:
                    verdict = correlate.confirm_candidate(
                        _ip, baseline, fetch_fn=lambda u: getpage_main(u, usetor=False))
                    oob_result.setdefault('confirmations', []).append(verdict)
                    logging.warning('OOB deanon: origin called back from %s => %s',
                                    _ip, verdict.get('verdict'))
                except Exception as e:
                    logging.debug('oob confirmation failed for %s: %s', _ip, e)
        except Exception as e:
            logging.error('oob poll failed (%s)', e)

    # Calculate scan duration
    end_time = time.time()
    duration = end_time - start_time
    duration_str = f"{int(duration // 60)}m {int(duration % 60)}s"

    # Determine if HTML report should be generated
    should_generate_html = args.html_report or (os.environ.get('GITHUB_ACTIONS') and args.loglevel == 'DEBUG')

    logging.info(f"HTML Report Decision: html_report={args.html_report}, GITHUB_ACTIONS={os.environ.get('GITHUB_ACTIONS')}, loglevel={args.loglevel}, will_generate={should_generate_html}")

    # Generate HTML report if requested
    if should_generate_html:
        logging.info("🎨 Generating HTML report...")

        try:
            # Prepare scan data for report
            scan_data = {
                'target': args.target,
                'scan_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'duration': duration_str,
                'summary': {
                    'fqdn': fqdn,
                    'status_code': requestobject.status_code,
                    'open_ports_count': len(portscan_data.get('ports', [])) if portscan_data else 0,
                    'paths_discovered_count': len(discovered_paths) if discovered_paths else 0,
                    'use_tor': torstate
                },
                'discovered_paths': discovered_paths or [],
                'origin_leaks': origin_leaks,
                'oob': oob_result,
                'headers': header_data,
                'all_headers': dict(requestobject.headers),  # Pass all raw headers
                'title': title_data,
                'certificate': getcert_data if args.target.startswith('https') else None,
                'ports': portscan_data,
                'favicon': favicon_data,
                'analytics': analytics_data,
                'contentleak': contentleak_data,
                'robotsmap': robotsmap_data,
                'tls_fingerprint': tlsfingerprint_data,
                'cryptocurrency': cryptocurrency_data,
                'pagespider': pagespider_data,
                'domains': domains_data,
                'deanon_candidates': deanon_candidates,
                'reverse_resolved': reverse_resolved
            }

            # Generate HTML
            logging.info("📝 Rendering HTML template...")
            html_content = generate_html_report(scan_data)
            logging.info(f"✓ Generated {len(html_content)} bytes of HTML")

            # Determine output path
            if args.html_report:
                output_path = args.html_report
            else:
                # Default path for GitHub Actions
                output_path = '/tmp/bebop-report.html'

            # Save report
            logging.info(f"💾 Saving HTML report to: {output_path}")
            if save_html_report(html_content, output_path):
                logging.info(f"✅ HTML report saved successfully to: {output_path}")
            else:
                logging.error("❌ Failed to save HTML report")

        except Exception as e:
            logging.error(f"❌ Error generating HTML report: {e}")
            import traceback
            logging.error(traceback.format_exc())
    else:
        logging.info("ℹ️  HTML report generation skipped (set loglevel=DEBUG in GitHub Actions to enable)")


if __name__ == '__main__':
    main()
