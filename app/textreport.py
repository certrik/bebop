#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Plain-text / Markdown findings report.

A third output format alongside the log stream and the HTML report. This one is
deliberately minimal: it lists only *findings* - no log lines, no errors, no
commentary - as Markdown (which also reads fine as plain text). Empty sections
are omitted, so the report is exactly as long as there is something to show.
"""
import datetime


def _esc(value):
    """Escape a cell for a Markdown table."""
    return str(value).replace('|', '\\|').replace('\n', ' ').strip()


def _table(headers, rows):
    out = ['| ' + ' | '.join(headers) + ' |',
           '| ' + ' | '.join('---' for _ in headers) + ' |']
    for row in rows:
        out.append('| ' + ' | '.join(_esc(c) for c in row) + ' |')
    return out


def _section(title, lines):
    """Return a titled section, or [] when there is nothing to show."""
    if not lines:
        return []
    return ['', f'## {title}', ''] + lines


def _deanon_section(data):
    cands = data.get('deanon_candidates') or []
    rows = []
    for c in cands:
        conf = c.get('confirmation') or {}
        rows.append([
            c.get('candidate', '?'),
            conf.get('verdict', '?'),
            ', '.join(conf.get('matches') or []) or '-',
            ', '.join(c.get('categories') or []) or '-',
            ', '.join(c.get('sources') or []) or '-',
            conf.get('url') or '-',
        ])
    if not rows:
        return []
    return _table(['candidate', 'verdict', 'matches', 'selector categories',
                   'sources', 'url'], rows)


def _verdict_rows(records):
    rows = []
    for r in records or []:
        if not isinstance(r, dict):
            continue
        rows.append([r.get('candidate', '?'), r.get('verdict', '?'),
                     ', '.join(r.get('matches') or []) or '-',
                     r.get('url') or '-'])
    return rows


def _origin_leak_section(data):
    rows = _verdict_rows(data.get('origin_leaks'))
    if not rows:
        return []
    return _table(['leaked IP', 'verdict', 'matches', 'url'], rows)


def _oob_section(data):
    oob = data.get('oob') or {}
    ips = oob.get('source_ips') or []
    if not ips:
        return []
    lines = [f'- callback source IP: `{ip}`' for ip in ips]
    conf_rows = _verdict_rows(oob.get('confirmations'))
    if conf_rows:
        lines += [''] + _table(['callback IP', 'verdict', 'matches', 'url'], conf_rows)
    return lines


def _ports_section(data):
    ports = (data.get('ports') or {}).get('ports') or []
    rows = []
    for p in ports:
        if not isinstance(p, dict):
            continue
        svc = ' '.join(str(x) for x in (p.get('name'), p.get('product'),
                                        p.get('version')) if x) or '-'
        cpe = p.get('cpe')
        if isinstance(cpe, (list, tuple)):
            cpe = ', '.join(str(c) for c in cpe)
        rows.append([p.get('port', '?'), svc, p.get('ostype') or '-',
                     cpe or '-', p.get('banner') or '-'])
    if not rows:
        return []
    lines = _table(['port', 'service', 'ostype', 'cpe', 'banner'], rows)
    # SSH host-key fingerprints / banner analysis, when present
    for p in ports:
        if not isinstance(p, dict):
            continue
        if p.get('ssh_fingerprints'):
            lines.append(f'- **SSH host keys ({p.get("port")}):** {p["ssh_fingerprints"]}')
        if p.get('ssh_banner_analysis'):
            lines.append(f'- **SSH banner ({p.get("port")}):** {p["ssh_banner_analysis"]}')
    return lines


def _paths_section(data):
    paths = data.get('discovered_paths') or []
    rows = []
    for p in paths:
        if not isinstance(p, dict):
            continue
        ind = p.get('indicators') or {}
        leaked = ((ind.get('public_ips') or []) + (ind.get('private_ips') or [])
                  + (ind.get('hostnames') or []))
        rows.append([p.get('method', 'GET'), p.get('path', '?'),
                     p.get('status_code', '?'),
                     p.get('description', '-'),
                     p.get('matched_text') or '-',
                     ', '.join(leaked) or '-'])
    if not rows:
        return []
    return _table(['method', 'path', 'code', 'description', 'matched', 'origin indicators'], rows)


def _certificate_section(data):
    cert = data.get('certificate')
    if not isinstance(cert, dict):
        return []
    lines = []
    fields = [('common_name', 'Common Name'), ('subject', 'Subject'),
              ('issuer', 'Issuer'), ('serial', 'Serial')]
    for key, label in fields:
        if cert.get(key):
            lines.append(f'- **{label}:** {cert[key]}')
    alt = cert.get('alt_names')
    if alt:
        lines.append(f'- **SANs:** {", ".join(alt)}')
    for key, label in [('not_before', 'Not before'), ('not_after', 'Not after')]:
        if cert.get(key):
            lines.append(f'- **{label}:** {cert[key]}')
    return lines


def _tls_section(data):
    tls = data.get('tls_fingerprint')
    if not isinstance(tls, dict):
        return []
    lines = []
    if tls.get('jarm'):
        lines.append(f'- **JARM:** `{tls["jarm"]}`')
    fps = tls.get('cert_fingerprints') or {}
    for algo in ('sha256', 'sha1', 'md5'):
        if fps.get(algo):
            lines.append(f'- **cert {algo}:** `{fps[algo]}`')
    analysis = tls.get('tls_analysis') or {}
    if analysis.get('supported_versions'):
        lines.append(f'- **TLS versions:** {", ".join(analysis["supported_versions"])}')
    return lines


def _favicon_section(data):
    fav = data.get('favicon')
    if not isinstance(fav, dict):
        return []
    lines = []
    if fav.get('mmh3') is not None:
        lines.append(f'- **mmh3:** `{fav["mmh3"]}`')
    if fav.get('md5'):
        lines.append(f'- **md5:** `{fav["md5"]}`')
    if fav.get('location'):
        lines.append(f'- **location:** {fav["location"]}')
    if fav.get('common'):
        lines.append('- **note:** matches a common favicon (low uniqueness)')
    return lines


def _headers_section(data):
    hdr = data.get('headers')
    if not isinstance(hdr, dict):
        return []
    lines = []
    if hdr.get('interesting_headers'):
        lines.append(f'- **interesting headers:** {", ".join(hdr["interesting_headers"])}')
    if hdr.get('csp_domains'):
        lines.append(f'- **CSP domains:** {", ".join(hdr["csp_domains"])}')
    if hdr.get('cors_origin'):
        lines.append(f'- **CORS origin:** {hdr["cors_origin"]}')
    for k, v in (hdr.get('security_headers') or {}).items():
        lines.append(f'- **{k}:** {v}')
    return lines


def _contentleak_section(data):
    leak = data.get('contentleak')
    if not isinstance(leak, dict):
        return []
    lines = []
    hosts = sorted({r.get('host') for r in (leak.get('clearnet_resources') or [])
                    if r.get('host')})
    if hosts:
        lines.append(f'- **clearnet resources loaded from:** {", ".join(hosts)}')
    if leak.get('outbound_hosts'):
        lines.append(f'- **outbound clearnet links:** {", ".join(leak["outbound_hosts"])}')
    onion = leak.get('onion_location') or {}
    if onion.get('onion_location'):
        lines.append(f'- **Onion-Location:** {onion["onion_location"]}')
    if leak.get('emails'):
        lines.append(f'- **e-mails:** {", ".join(leak["emails"])}')
    for canon in (onion.get('canonical_links') or []):
        lines.append(f'- **canonical/alternate link:** {canon}')
    for key in (leak.get('pgp_keys') or []):
        if key.get('id'):
            lines.append(f'- **PGP key id:** {key["id"]}')
    bh = leak.get('body_hash') or {}
    for algo in ('mmh3', 'md5', 'sha1', 'sha256'):
        if bh.get(algo) is not None:
            lines.append(f'- **body {algo}:** `{bh[algo]}`')
    return lines


def _robotsmap_section(data):
    rm = data.get('robotsmap')
    if not isinstance(rm, dict):
        return []
    lines = []
    robots = rm.get('robots_txt') or {}
    disallowed = robots.get('disallowed_paths') or []
    if disallowed:
        lines.append(f'- **robots.txt disallowed ({len(disallowed)}):** '
                     + ', '.join(sorted({d.get('path', '') for d in disallowed if d.get('path')})))
    if robots.get('sitemaps'):
        lines.append(f'- **robots.txt sitemaps:** {", ".join(robots["sitemaps"])}')
    for sm in (rm.get('sitemaps') or []):
        urls = (sm.get('data') or {}).get('urls') or []
        if urls:
            locs = [u.get('loc') for u in urls if isinstance(u, dict) and u.get('loc')]
            lines.append(f'- **sitemap {sm.get("url", "")} ({len(locs)} URLs):** '
                         + ', '.join(locs[:50]) + (' …' if len(locs) > 50 else ''))
    return lines


def _pagespider_section(data):
    ps = data.get('pagespider')
    if not isinstance(ps, dict):
        return []
    lines = []
    same = ps.get('samedomain') or []
    ext = ps.get('extdomain') or []
    emails = ps.get('emails') or []
    if same:
        lines.append(f'- **same-domain links ({len(same)}):** '
                     + ', '.join(same[:50]) + (' …' if len(same) > 50 else ''))
    if ext:
        lines.append(f'- **external links ({len(ext)}):** '
                     + ', '.join(ext[:50]) + (' …' if len(ext) > 50 else ''))
    if emails:
        lines.append(f'- **e-mails:** {", ".join(emails)}')
    return lines


def _all_headers_section(data):
    headers = data.get('all_headers')
    if not isinstance(headers, dict) or not headers:
        return []
    return _table(['header', 'value'], [[k, v] for k, v in headers.items()])


def _analytics_section(data):
    an = data.get('analytics')
    if not isinstance(an, dict) or not an:
        return []
    lines = []
    for provider, ids in an.items():
        vals = ids if isinstance(ids, (list, tuple, set)) else [ids]
        vals = [str(v) for v in vals if v]
        if vals:
            lines.append(f'- **{provider}:** {", ".join(vals)}')
    return lines


def _crypto_section(data):
    coins = data.get('cryptocurrency')
    if not isinstance(coins, dict):
        return []
    lines = []
    for coin, addrs in coins.items():
        if addrs:
            for a in addrs:
                lines.append(f'- **{coin}:** `{a}`')
    return lines


def _domains_section(data):
    lines = []
    domains = data.get('domains') or []
    if domains:
        lines.append(f'- **resolving domains:** {", ".join(domains)}')
    rev = data.get('reverse_resolved') or {}
    for ip, doms in rev.items():
        if doms:
            lines.append(f'- **{ip} → :** {", ".join(doms)}')
    return lines


def _title_section(data):
    title = data.get('title')
    if not title:
        return []
    return [f'- {title}']


def generate_text_report(scan_data):
    """Render scan_data as a findings-only Markdown report (string)."""
    target = scan_data.get('target', 'unknown')
    summary = scan_data.get('summary') or {}
    lines = [
        f'# bebop findings — {target}',
        '',
        f'- **Target:** {target}',
    ]
    if summary.get('fqdn'):
        lines.append(f'- **FQDN:** {summary["fqdn"]}')
    lines.append(f'- **Scan date:** {scan_data.get("scan_date", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}')
    if scan_data.get('duration'):
        lines.append(f'- **Duration:** {scan_data["duration"]}')
    lines.append(f'- **Routing:** {"Tor" if summary.get("use_tor", True) else "clearnet"}')

    sections = [
        ('Deanonymisation candidates', _deanon_section(scan_data)),
        ('Origin IPs leaked by config checks', _origin_leak_section(scan_data)),
        ('Out-of-band callbacks', _oob_section(scan_data)),
        ('Open ports', _ports_section(scan_data)),
        ('Discovered paths', _paths_section(scan_data)),
        ('Certificate', _certificate_section(scan_data)),
        ('TLS / JARM fingerprints', _tls_section(scan_data)),
        ('Favicon', _favicon_section(scan_data)),
        ('HTTP headers of interest', _headers_section(scan_data)),
        ('Page title', _title_section(scan_data)),
        ('Content leaks', _contentleak_section(scan_data)),
        ('Analytics / tracking IDs', _analytics_section(scan_data)),
        ('Cryptocurrency wallets', _crypto_section(scan_data)),
        ('Robots.txt & sitemaps', _robotsmap_section(scan_data)),
        ('Page spider (links & e-mails)', _pagespider_section(scan_data)),
        ('Domains', _domains_section(scan_data)),
        ('All response headers', _all_headers_section(scan_data)),
    ]
    for title, body in sections:
        lines += _section(title, body)

    return '\n'.join(lines).rstrip() + '\n'


def save_text_report(content, output_path):
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except OSError as e:
        import logging
        logging.getLogger(__name__).error('failed to save text report: %s', e)
        return False
