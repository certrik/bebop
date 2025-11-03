#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import logging
import asyncio
import argparse

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
from app.robotsmap import main as robotsmap_main
from app.tlsfingerprint import main as tlsfingerprint_main
from app.utilities import preflight, getfqdn, getbaseurl, validurl, getport


def main():
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
    args = parser.parse_args()

    logging.basicConfig(
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
        cliart_main.prints()

    if args.clearnet is True:
        logging.critical('clearnet routing enabled..')
        torstate = False
    else:
        logging.debug('tor routing enabled..')
        torstate = True
        preflight()

    if not validurl(args.target):
        if validurl('http://' + args.target):
            args.target = 'http://' + args.target
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

    requestobject = getpage_main(args.target, usetor=torstate)
    if requestobject is None:
        logging.error('failed to retrieve page')
        sys.exit(1)
    if requestobject.status_code != 200:
        logging.warning('unexpected response code: %s', requestobject.status_code)
    if args.target.startswith('https'):
        targetport = getport(args.target)
        getcert_data = getcert_main(fqdn, port=targetport)

    title_main(requestobject)
    header_data = headers_main(requestobject)
    asyncio.run(configcheck_main(url_base, usetor=torstate))
    favicon_data = favicon_main(url_base, requestobject, usetor=torstate)
    pagespider_data = pagespider_main(requestobject, usetor=torstate, skip_queryurl=True)
    cryptocurrency_data = cryptocurrency_main(requestobject.text)

    # NEW: Analytics and tracking code extraction
    analytics_data = analytics_main(requestobject)

    # NEW: Robots.txt and sitemap analysis
    robotsmap_data = robotsmap_main(url_base, usetor=torstate)

    # NEW: TLS fingerprinting (for HTTPS sites)
    if args.target.startswith('https'):
        tlsfingerprint_data = tlsfingerprint_main(fqdn, port=targetport, usetor=torstate)

    # Get the IP address from the request object
    if hasattr(requestobject, 'raw') and hasattr(requestobject.raw, 'connection') and hasattr(requestobject.raw.connection, 'sock'):
        ip_address = requestobject.raw.connection.sock.getpeername()[0]
        logging.info(f"IP address: {ip_address}")
        # Use finddomains to discover domains resolving to this IP
        domains_data = finddomains_main(ip_address)
        if domains_data:
            logging.info(f"Found {len(domains_data)} domains resolving to {ip_address}")
            for domain in domains_data:
                logging.info(f"Domain: {domain}")

    for item in pagespider_data['samedomain']:
        itemsource = getpage_main(item)
        if itemsource is not None:
            opendir_main(itemsource)
            cryptocurrency_main(requestobject.text)
    portscan_main(fqdn, useragent=args.useragent, usetor=torstate)


if __name__ == '__main__':
    main()
