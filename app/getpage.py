#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
import logging
import requests

from app.utilities import getsocks, useragentstr

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()

# (connect, read) timeouts in seconds. Tor needs a generous connect budget: a
# cold daemon has to fetch the onion descriptor and build a rendezvous circuit
# before the first byte, which routinely takes well over the old flat 30s.
# Clearnet fetches get a tighter budget since there is no circuit to build.
_TOR_TIMEOUT = (90, 60)
_CLEARNET_TIMEOUT = (15, 30)
# Total attempts (initial try + retries). Tor circuits are flaky and a second
# attempt frequently succeeds where the first timed out.
_TOR_ATTEMPTS = 3
_CLEARNET_ATTEMPTS = 2
_BACKOFF = 3  # seconds, multiplied by the attempt number


def main(weblocation, usetor=True, timeout=None, attempts=None):
    if usetor:
        reqproxies = getsocks()
    else:
        reqproxies = None
    if timeout is None:
        timeout = _TOR_TIMEOUT if usetor else _CLEARNET_TIMEOUT
    if attempts is None:
        attempts = _TOR_ATTEMPTS if usetor else _CLEARNET_ATTEMPTS

    logging.debug('requesting: %s - usetor:%s (timeout=%s, attempts=%s)',
                  weblocation, usetor, timeout, attempts)
    logging.debug('using proxies: %s', reqproxies)

    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            siterequest = requests.get(
                weblocation,
                proxies=reqproxies,
                verify=False,
                timeout=timeout,
                headers={'User-Agent': useragentstr},
                allow_redirects=True
            )
            if siterequest.history:
                for resp in siterequest.history:
                    log.info('redirect: %s (%s)', resp.url, resp.status_code)
                log.info("followed to: %s", siterequest.url)
            log.debug('request took: %s seconds', siterequest.elapsed.total_seconds())
            return siterequest
        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError) as rece:
            last_error = rece
            if attempt < attempts:
                backoff = _BACKOFF * attempt
                log.warning('retrieval of %s failed (attempt %s/%s): %s - retrying in %ss',
                            weblocation, attempt, attempts, rece, backoff)
                time.sleep(backoff)
            else:
                log.error('retrieval of %s failed after %s attempts: %s',
                          weblocation, attempts, rece)
    return None
