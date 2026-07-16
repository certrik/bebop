import socket
import socks
import logging
from app.subprocessors import (
    query_resolutions_virustotal,
    query_resolutions_urlscan,
    query_resolutions_securitytrails,
    query_resolutions_validin
)

from app.utilities import getproxyvalue

log = logging.getLogger(__name__)

def get_proxy_socket():
    proxyaddr, proxyport = getproxyvalue()
    socks.set_default_proxy(socks.SOCKS5, proxyaddr, proxyport)
    return socks.socksocket()

def reverse_dns_lookup(ip_address):
    try:
        # Use a local proxy-enabled socket
        with get_proxy_socket() as s:
            hostname, _, _ = s.gethostbyaddr(ip_address)
        return hostname
    except Exception as e:
        logging.error(f"error in rDNS lookup for {ip_address}: {e}")
        return None

def check_hostname_resolvematch(hostnames, target_ip):
    resolved_hostnames = []
    for hostname in hostnames:
        try:
            # Use a local proxy-enabled socket
            with get_proxy_socket() as s:
                ip = s.gethostbyname(hostname)
            if ip == target_ip:
                resolved_hostnames.append(hostname)
        except Exception as e:
            logging.debug(f"failed to resolve {hostname}: {e}")
    return resolved_hostnames

def main(ip):
    log.info('starting finddomains')
    reverse_dns_hostname = reverse_dns_lookup(ip)
    log.info('querying virustotal for resolutions')
    vtires = query_resolutions_virustotal(ip)
    log.info('querying urlscan for resolutions')
    urlsres = query_resolutions_urlscan(ip)
    log.info('querying securitytrails for resolutions')
    strailres = query_resolutions_securitytrails(ip)
    log.info('querying validin for historical resolutions')
    validinres = query_resolutions_validin(ip)
    combined_hostnames = vtires.union(urlsres, strailres, validinres)
    if reverse_dns_hostname:
        combined_hostnames.add(reverse_dns_hostname)
    log.debug(f"total hostnames: {combined_hostnames}")
    log.info(f'found {len(combined_hostnames)} unique hostnames, checking resolution')
    resolved_hostnames = check_hostname_resolvematch(combined_hostnames, ip)
    log.info(f"found {len(resolved_hostnames)} hostnames resolving to {ip}")
    # Validin's edge is history: a domain that *used* to point at the origin is
    # a strong deanon lead even if it no longer resolves there, so its hits are
    # kept as candidates rather than dropped by the current-resolution filter.
    all_candidates = sorted(set(resolved_hostnames).union(validinres))
    log.debug(f"candidate hostnames: {all_candidates}")
    log.info(f"found {len(all_candidates)} candidate hostnames for {ip} "
             f"({len(resolved_hostnames)} currently resolving)")
    return all_candidates
