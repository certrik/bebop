#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTML Report Generator for bebop scan results
"""
import logging
import datetime
from html import escape

log = logging.getLogger(__name__)


def generate_html_report(scan_data):
    """
    Generate a comprehensive HTML report from scan data

    Args:
        scan_data: Dictionary containing all scan results

    Returns:
        str: HTML content
    """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>bebop Scan Report - {escape(scan_data.get('target', 'Unknown'))}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f0f23;
            color: #cccccc;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: #10101a;
            border: 1px solid #333;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px 8px 0 0;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        .header .meta {{
            margin-top: 15px;
            font-size: 0.9em;
            opacity: 0.8;
        }}
        .content {{
            padding: 30px;
        }}
        .section {{
            margin-bottom: 40px;
            background: #1a1a2e;
            border: 1px solid #2a2a3e;
            border-radius: 6px;
            padding: 25px;
        }}
        .section-title {{
            font-size: 1.8em;
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        .subsection {{
            margin: 20px 0;
        }}
        .subsection-title {{
            font-size: 1.3em;
            color: #8b9dc3;
            margin-bottom: 15px;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }}
        .info-item {{
            background: #252535;
            padding: 15px;
            border-radius: 4px;
            border-left: 3px solid #667eea;
        }}
        .info-item .label {{
            color: #8b9dc3;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .info-item .value {{
            color: #e0e0e0;
            word-break: break-all;
        }}
        .table-container {{
            overflow-x: auto;
            margin: 15px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #252535;
        }}
        th {{
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid #333;
        }}
        tr:hover {{
            background: #2a2a3e;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 2px;
        }}
        .badge-success {{
            background: #10b981;
            color: white;
        }}
        .badge-warning {{
            background: #f59e0b;
            color: white;
        }}
        .badge-danger {{
            background: #ef4444;
            color: white;
        }}
        .badge-info {{
            background: #3b82f6;
            color: white;
        }}
        .badge-secondary {{
            background: #6b7280;
            color: white;
        }}
        .code-block {{
            background: #1e1e2e;
            border: 1px solid #333;
            border-radius: 4px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #e0e0e0;
            margin: 10px 0;
        }}
        .list-item {{
            background: #252535;
            padding: 10px 15px;
            margin: 8px 0;
            border-radius: 4px;
            border-left: 3px solid #667eea;
        }}
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #666;
            font-style: italic;
        }}
        .warning-box {{
            background: #78350f;
            border: 1px solid #f59e0b;
            color: #fbbf24;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }}
        .success-box {{
            background: #064e3b;
            border: 1px solid #10b981;
            color: #6ee7b7;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 1px solid #333;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🧅 bebop Scan Report</h1>
            <div class="subtitle">Tor/Onion Service Deanonymization Analysis</div>
            <div class="meta">
                <strong>Target:</strong> {escape(scan_data.get('target', 'Unknown'))}<br>
                <strong>Scan Date:</strong> {scan_data.get('scan_date', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}<br>
                <strong>Duration:</strong> {scan_data.get('duration', 'Unknown')}
            </div>
        </div>

        <div class="content">
            {_generate_summary_section(scan_data)}
            {_generate_discovered_paths_section(scan_data)}
            {_generate_headers_section(scan_data)}
            {_generate_title_section(scan_data)}
            {_generate_ports_section(scan_data)}
            {_generate_certificate_section(scan_data)}
            {_generate_tls_fingerprint_section(scan_data)}
            {_generate_favicon_section(scan_data)}
            {_generate_analytics_section(scan_data)}
            {_generate_robotsmap_section(scan_data)}
            {_generate_cryptocurrency_section(scan_data)}
            {_generate_pagespider_section(scan_data)}
            {_generate_domains_section(scan_data)}
        </div>

        <div class="footer">
            Generated by <strong>bebop</strong> - Hidden Service Safari 👀 🧅 💻
        </div>
    </div>
</body>
</html>
"""
    return html


def _generate_summary_section(data):
    """Generate summary overview section"""
    summary = data.get('summary', {})

    html = f"""
    <div class="section">
        <h2 class="section-title">📊 Scan Summary</h2>
        <div class="info-grid">
            <div class="info-item">
                <div class="label">Target URL</div>
                <div class="value">{escape(data.get('target', 'N/A'))}</div>
            </div>
            <div class="info-item">
                <div class="label">FQDN</div>
                <div class="value">{escape(summary.get('fqdn', 'N/A'))}</div>
            </div>
            <div class="info-item">
                <div class="label">Status Code</div>
                <div class="value">{escape(str(summary.get('status_code', 'N/A')))}</div>
            </div>
            <div class="info-item">
                <div class="label">Open Ports</div>
                <div class="value">{summary.get('open_ports_count', 0)}</div>
            </div>
            <div class="info-item">
                <div class="label">Paths Discovered</div>
                <div class="value">{summary.get('paths_discovered_count', 0)}</div>
            </div>
            <div class="info-item">
                <div class="label">Routing</div>
                <div class="value">
                    <span class="badge badge-info">{('Tor' if summary.get('use_tor') else 'Clearnet')}</span>
                </div>
            </div>
        </div>
    </div>
    """
    return html


def _generate_discovered_paths_section(data):
    """Generate section showing discovered file paths with response codes"""
    paths = data.get('discovered_paths', [])

    if not paths:
        return f"""
        <div class="section">
            <h2 class="section-title">📁 Discovered Paths</h2>
            <div class="empty-state">No interesting paths discovered</div>
        </div>
        """

    rows = ""
    for path in paths:
        status_code = path.get('status_code', 'Unknown')
        badge_class = 'badge-success' if status_code == 200 else 'badge-warning' if status_code in [301, 302, 403] else 'badge-danger'

        rows += f"""
        <tr>
            <td><code>{escape(path.get('path', 'N/A'))}</code></td>
            <td><span class="badge {badge_class}">{escape(str(status_code))}</span></td>
            <td>{escape(path.get('description', 'N/A'))}</td>
            <td>{escape(path.get('matched_text', 'N/A') if path.get('matched_text') else '-')}</td>
        </tr>
        """

    html = f"""
    <div class="section">
        <h2 class="section-title">📁 Discovered Paths</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Path</th>
                        <th>Status</th>
                        <th>Description</th>
                        <th>Matched Content</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
    </div>
    """
    return html


def _generate_headers_section(data):
    """Generate HTTP headers section"""
    headers_data = data.get('headers', {})

    if not headers_data:
        return ""

    # Interesting headers
    interesting = headers_data.get('interesting_headers', [])
    interesting_html = ""
    if interesting:
        for header in interesting:
            interesting_html += f'<span class="badge badge-info">{escape(header)}</span>'
    else:
        interesting_html = "<span class='empty-state'>None detected</span>"

    # CSP domains
    csp_domains = headers_data.get('csp_domains', [])
    csp_html = ""
    if csp_domains:
        for domain in csp_domains:
            csp_html += f'<div class="list-item">{escape(domain)}</div>'
    else:
        csp_html = "<div class='empty-state'>No CSP domains found</div>"

    # CORS
    cors_origin = headers_data.get('cors_origin')
    cors_html = f"<div class='list-item'>{escape(cors_origin)}</div>" if cors_origin else "<div class='empty-state'>No CORS headers</div>"

    # HTTP/2 info
    http2_info = headers_data.get('http2_info', {})
    http2_html = ""
    if http2_info:
        for key, value in http2_info.items():
            http2_html += f"""
            <div class="info-item">
                <div class="label">{escape(key.replace('_', ' ').title())}</div>
                <div class="value">{escape(str(value))}</div>
            </div>
            """
    else:
        http2_html = "<div class='empty-state'>HTTP/1.1</div>"

    html = f"""
    <div class="section">
        <h2 class="section-title">📋 HTTP Headers Analysis</h2>

        <div class="subsection">
            <h3 class="subsection-title">Interesting Headers</h3>
            {interesting_html}
        </div>

        <div class="subsection">
            <h3 class="subsection-title">CSP Domains</h3>
            {csp_html}
        </div>

        <div class="subsection">
            <h3 class="subsection-title">CORS Origin</h3>
            {cors_html}
        </div>

        <div class="subsection">
            <h3 class="subsection-title">HTTP Protocol Info</h3>
            <div class="info-grid">
                {http2_html}
            </div>
        </div>
    </div>
    """
    return html


def _generate_title_section(data):
    """Generate page title section"""
    title = data.get('title')

    if not title:
        return ""

    html = f"""
    <div class="section">
        <h2 class="section-title">📄 Page Title</h2>
        <div class="code-block">{escape(title)}</div>
    </div>
    """
    return html


def _generate_ports_section(data):
    """Generate open ports section"""
    ports_data = data.get('ports', {})
    ports = ports_data.get('ports', [])

    if not ports:
        return ""

    rows = ""
    for port in ports:
        port_num = port.get('port', 'N/A')
        service = port.get('name', 'unknown')
        product = port.get('product', '')
        version = port.get('version', '')
        ostype = port.get('ostype', '')

        ssh_fp = port.get('ssh_fingerprints')
        ssh_html = ""
        if ssh_fp:
            ssh_html = f"<br><small>🔑 SSH Fingerprints: {len(ssh_fp.get('sha256', []))} SHA256, {len(ssh_fp.get('md5', []))} MD5</small>"

        rows += f"""
        <tr>
            <td><strong>{escape(str(port_num))}</strong></td>
            <td><span class="badge badge-success">{escape(service)}</span></td>
            <td>{escape(product)} {escape(version)}</td>
            <td>{escape(ostype) if ostype else '-'}</td>
            <td>{escape(port.get('banner', '') if port.get('banner') else '-')}{ssh_html}</td>
        </tr>
        """

    html = f"""
    <div class="section">
        <h2 class="section-title">🔌 Open Ports</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Product/Version</th>
                        <th>OS</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        <div class="meta" style="margin-top: 15px; color: #666;">
            Scan completed in {ports_data.get('time', 'N/A')} seconds
        </div>
    </div>
    """
    return html


def _generate_certificate_section(data):
    """Generate SSL/TLS certificate section"""
    cert = data.get('certificate')

    if not cert:
        return ""

    html = f"""
    <div class="section">
        <h2 class="section-title">🔒 SSL/TLS Certificate</h2>
        <div class="info-grid">
            <div class="info-item">
                <div class="label">Common Name (CN)</div>
                <div class="value">{escape(cert.get('CN', 'N/A'))}</div>
            </div>
            <div class="info-item">
                <div class="label">Organization (O)</div>
                <div class="value">{escape(cert.get('O', 'N/A'))}</div>
            </div>
            <div class="info-item">
                <div class="label">Issuer</div>
                <div class="value">{escape(cert.get('issuer', 'N/A'))}</div>
            </div>
            <div class="info-item">
                <div class="label">Valid From</div>
                <div class="value">{escape(cert.get('notBefore', 'N/A'))}</div>
            </div>
            <div class="info-item">
                <div class="label">Valid Until</div>
                <div class="value">{escape(cert.get('notAfter', 'N/A'))}</div>
            </div>
            <div class="info-item">
                <div class="label">Serial Number</div>
                <div class="value">{escape(cert.get('serialNumber', 'N/A'))}</div>
            </div>
        </div>
    </div>
    """
    return html


def _generate_tls_fingerprint_section(data):
    """Generate TLS fingerprinting section"""
    tls = data.get('tls_fingerprint')

    if not tls:
        return ""

    # TLS versions supported
    versions_html = ""
    if tls.get('supported_versions'):
        for ver in tls['supported_versions']:
            versions_html += f'<span class="badge badge-success">{escape(ver)}</span>'

    # Certificate fingerprints
    cert_fp = tls.get('certificate_fingerprints', {})
    cert_html = ""
    if cert_fp:
        cert_html = f"""
        <div class="info-grid">
            <div class="info-item">
                <div class="label">SHA256</div>
                <div class="value"><code>{escape(cert_fp.get('sha256', 'N/A'))}</code></div>
            </div>
            <div class="info-item">
                <div class="label">SHA1</div>
                <div class="value"><code>{escape(cert_fp.get('sha1', 'N/A'))}</code></div>
            </div>
            <div class="info-item">
                <div class="label">MD5</div>
                <div class="value"><code>{escape(cert_fp.get('md5', 'N/A'))}</code></div>
            </div>
        </div>
        """

    html = f"""
    <div class="section">
        <h2 class="section-title">🔐 TLS/SSL Fingerprinting</h2>

        <div class="subsection">
            <h3 class="subsection-title">Supported TLS Versions</h3>
            {versions_html if versions_html else '<div class="empty-state">No data</div>'}
        </div>

        <div class="subsection">
            <h3 class="subsection-title">Certificate Fingerprints</h3>
            {cert_html if cert_html else '<div class="empty-state">No data</div>'}
        </div>
    </div>
    """
    return html


def _generate_favicon_section(data):
    """Generate favicon section"""
    favicon = data.get('favicon')

    if not favicon:
        return ""

    html = f"""
    <div class="section">
        <h2 class="section-title">🎨 Favicon Analysis</h2>
        <div class="info-grid">
            <div class="info-item">
                <div class="label">MD5 Hash</div>
                <div class="value"><code>{escape(favicon.get('md5', 'N/A'))}</code></div>
            </div>
            <div class="info-item">
                <div class="label">Location</div>
                <div class="value">{escape(favicon.get('location', 'N/A'))}</div>
            </div>
        </div>
    </div>
    """
    return html


def _generate_analytics_section(data):
    """Generate analytics and tracking section"""
    analytics = data.get('analytics', {})

    if not analytics or not any(analytics.values()):
        return ""

    sections_html = ""

    tracking_platforms = [
        ('google_analytics', 'Google Analytics', 'badge-danger'),
        ('google_tag_manager', 'Google Tag Manager', 'badge-danger'),
        ('facebook_pixel', 'Facebook Pixel', 'badge-info'),
        ('yandex_metrica', 'Yandex Metrica', 'badge-warning'),
        ('matomo', 'Matomo/Piwik', 'badge-success'),
        ('cloudflare_analytics', 'Cloudflare Analytics', 'badge-info'),
        ('hotjar', 'Hotjar', 'badge-danger'),
        ('mixpanel', 'Mixpanel', 'badge-info'),
        ('segment', 'Segment', 'badge-warning'),
        ('amplitude', 'Amplitude', 'badge-info'),
        ('heap', 'Heap', 'badge-info'),
        ('google_adsense', 'Google AdSense', 'badge-danger'),
    ]

    for key, name, badge_class in tracking_platforms:
        values = analytics.get(key, [])
        if values:
            items_html = ""
            for value in values:
                items_html += f'<div class="list-item"><code>{escape(value)}</code></div>'

            sections_html += f"""
            <div class="subsection">
                <h3 class="subsection-title">
                    <span class="badge {badge_class}">{name}</span>
                </h3>
                {items_html}
            </div>
            """

    if not sections_html:
        return ""

    html = f"""
    <div class="section">
        <h2 class="section-title">📈 Analytics & Tracking Codes</h2>
        {sections_html}
    </div>
    """
    return html


def _generate_robotsmap_section(data):
    """Generate robots.txt and sitemap section"""
    robotsmap = data.get('robotsmap', {})

    if not robotsmap:
        return ""

    robots = robotsmap.get('robots', {})
    sitemaps = robotsmap.get('sitemaps', [])

    # Robots.txt
    robots_html = ""
    if robots:
        disallowed = robots.get('disallowed_paths', [])
        allowed = robots.get('allowed_paths', [])
        sitemap_urls = robots.get('sitemaps', [])

        if disallowed:
            robots_html += "<div class='subsection'><h3 class='subsection-title'>Disallowed Paths</h3>"
            for path in disallowed[:20]:  # Limit to 20
                robots_html += f"<div class='list-item'><code>{escape(path)}</code></div>"
            if len(disallowed) > 20:
                robots_html += f"<div class='empty-state'>... and {len(disallowed) - 20} more</div>"
            robots_html += "</div>"

        if sitemap_urls:
            robots_html += "<div class='subsection'><h3 class='subsection-title'>Sitemap URLs</h3>"
            for url in sitemap_urls:
                robots_html += f"<div class='list-item'>{escape(url)}</div>"
            robots_html += "</div>"

    # Sitemaps
    sitemap_html = ""
    if sitemaps:
        for sitemap in sitemaps:
            urls = sitemap.get('urls', [])
            sitemap_html += f"<div class='subsection'><h3 class='subsection-title'>Sitemap: {escape(sitemap.get('url', 'Unknown'))}</h3>"
            sitemap_html += f"<div class='info-item'><div class='label'>Total URLs</div><div class='value'>{len(urls)}</div></div>"
            if urls:
                sitemap_html += "<div class='table-container'><table><thead><tr><th>URL</th><th>Priority</th><th>Change Freq</th></tr></thead><tbody>"
                for url in urls[:10]:  # Show first 10
                    sitemap_html += f"""
                    <tr>
                        <td><code>{escape(url.get('loc', 'N/A'))}</code></td>
                        <td>{escape(url.get('priority', '-'))}</td>
                        <td>{escape(url.get('changefreq', '-'))}</td>
                    </tr>
                    """
                if len(urls) > 10:
                    sitemap_html += f"<tr><td colspan='3' class='empty-state'>... and {len(urls) - 10} more URLs</td></tr>"
                sitemap_html += "</tbody></table></div>"
            sitemap_html += "</div>"

    if not robots_html and not sitemap_html:
        return ""

    html = f"""
    <div class="section">
        <h2 class="section-title">🤖 Robots.txt & Sitemaps</h2>
        {robots_html}
        {sitemap_html}
    </div>
    """
    return html


def _generate_cryptocurrency_section(data):
    """Generate cryptocurrency wallets section"""
    crypto = data.get('cryptocurrency', {})

    if not crypto or not any(crypto.values()):
        return ""

    wallets_html = ""

    if crypto.get('btc'):
        wallets_html += "<div class='subsection'><h3 class='subsection-title'>Bitcoin (BTC)</h3>"
        for wallet in crypto['btc']:
            wallets_html += f"<div class='list-item'><code>{escape(wallet)}</code></div>"
        wallets_html += "</div>"

    if crypto.get('eth'):
        wallets_html += "<div class='subsection'><h3 class='subsection-title'>Ethereum (ETH)</h3>"
        for wallet in crypto['eth']:
            wallets_html += f"<div class='list-item'><code>{escape(wallet)}</code></div>"
        wallets_html += "</div>"

    if crypto.get('xmr'):
        wallets_html += "<div class='subsection'><h3 class='subsection-title'>Monero (XMR)</h3>"
        for wallet in crypto['xmr']:
            wallets_html += f"<div class='list-item'><code>{escape(wallet)}</code></div>"
        wallets_html += "</div>"

    if not wallets_html:
        return ""

    html = f"""
    <div class="section">
        <h2 class="section-title">💰 Cryptocurrency Wallets</h2>
        {wallets_html}
    </div>
    """
    return html


def _generate_pagespider_section(data):
    """Generate page spider section"""
    spider = data.get('pagespider', {})

    if not spider:
        return ""

    same_domain = spider.get('samedomain', [])
    ext_domain = spider.get('extdomain', [])
    emails = spider.get('emails', [])

    html_content = ""

    if same_domain:
        html_content += "<div class='subsection'><h3 class='subsection-title'>Same Domain Links</h3>"
        for link in same_domain[:20]:
            html_content += f"<div class='list-item'>{escape(link)}</div>"
        if len(same_domain) > 20:
            html_content += f"<div class='empty-state'>... and {len(same_domain) - 20} more</div>"
        html_content += "</div>"

    if ext_domain:
        html_content += "<div class='subsection'><h3 class='subsection-title'>External Domain Links</h3>"
        for link in ext_domain[:20]:
            html_content += f"<div class='list-item'>{escape(link)}</div>"
        if len(ext_domain) > 20:
            html_content += f"<div class='empty-state'>... and {len(ext_domain) - 20} more</div>"
        html_content += "</div>"

    if emails:
        html_content += "<div class='subsection'><h3 class='subsection-title'>Email Addresses</h3>"
        for email in emails:
            html_content += f"<div class='list-item'>{escape(email)}</div>"
        html_content += "</div>"

    if not html_content:
        return ""

    html = f"""
    <div class="section">
        <h2 class="section-title">🕷️ Page Spider Results</h2>
        {html_content}
    </div>
    """
    return html


def _generate_domains_section(data):
    """Generate related domains section"""
    domains = data.get('domains', [])

    if not domains:
        return ""

    domains_html = ""
    for domain in domains:
        domains_html += f"<div class='list-item'>{escape(domain)}</div>"

    html = f"""
    <div class="section">
        <h2 class="section-title">🌐 Related Domains</h2>
        <div class="info-item">
            <div class="label">Total Domains Found</div>
            <div class="value">{len(domains)}</div>
        </div>
        {domains_html}
    </div>
    """
    return html


def save_html_report(html_content, output_path):
    """
    Save HTML report to file

    Args:
        html_content: HTML string content
        output_path: Path to save the file
    """
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        log.info(f"HTML report saved to: {output_path}")
        return True
    except Exception as e:
        log.error(f"Failed to save HTML report: {e}")
        return False
