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
            {_generate_deanon_section(scan_data)}
            {_generate_discovered_paths_section(scan_data)}
            {_generate_headers_section(scan_data)}
            {_generate_title_section(scan_data)}
            {_generate_ports_section(scan_data)}
            {_generate_certificate_section(scan_data)}
            {_generate_tls_fingerprint_section(scan_data)}
            {_generate_favicon_section(scan_data)}
            {_generate_analytics_section(scan_data)}
            {_generate_contentleak_section(scan_data)}
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

        indicators = path.get('indicators') or {}
        leaked = (indicators.get('public_ips', []) or []) + (indicators.get('hostnames', []) or [])
        leaked_cell = escape(', '.join(leaked)) if leaked else '-'

        rows += f"""
        <tr>
            <td><code>{escape(path.get('path', 'N/A'))}</code></td>
            <td><span class="badge {badge_class}">{escape(str(status_code))}</span></td>
            <td>{escape(path.get('description', 'N/A'))}</td>
            <td>{escape(path.get('matched_text', 'N/A') if path.get('matched_text') else '-')}</td>
            <td>{leaked_cell}</td>
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
                        <th>Origin Indicators</th>
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
    all_headers = data.get('all_headers', {})

    if not headers_data and not all_headers:
        return ""

    # All HTTP Headers with values
    all_headers_html = ""
    if all_headers:
        # Create a table for all headers
        rows = ""
        for header_name, header_value in sorted(all_headers.items()):
            # Highlight interesting headers
            is_interesting = header_name.lower() in ['server', 'etag', 'x-powered-by', 'x-aspnet-version', 'x-generator']
            row_class = "style='background: #2a2a3e;'" if is_interesting else ""

            rows += f"""
            <tr {row_class}>
                <td><strong>{escape(header_name)}</strong></td>
                <td><code>{escape(header_value)}</code></td>
            </tr>
            """

        all_headers_html = f"""
        <div class="subsection">
            <h3 class="subsection-title">All HTTP Headers</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Header Name</th>
                            <th>Header Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
        """

    # CSP domains
    csp_domains = headers_data.get('csp_domains', [])
    csp_html = ""
    if csp_domains:
        csp_html += "<div class='subsection'><h3 class='subsection-title'>CSP Domains (Backend Servers Detected)</h3>"
        csp_html += "<p style='color: #8b9dc3; margin-bottom: 10px;'>These domains were found in Content-Security-Policy headers and may reveal backend infrastructure:</p>"
        for domain in csp_domains:
            csp_html += f'<div class="list-item"><span class="badge badge-warning">🔍</span> {escape(domain)}</div>'
        csp_html += "</div>"

    # CORS
    cors_origin = headers_data.get('cors_origin')
    cors_html = ""
    if cors_origin:
        cors_html = f"""
        <div class='subsection'>
            <h3 class='subsection-title'>CORS Origin (Cross-Origin Access)</h3>
            <p style='color: #8b9dc3; margin-bottom: 10px;'>The server allows cross-origin requests from:</p>
            <div class='list-item'><span class="badge badge-warning">🔗</span> {escape(cors_origin)}</div>
        </div>
        """

    # HTTP/2 info
    http2_info = headers_data.get('http2_info', {})
    http2_html = ""
    if http2_info and http2_info.get('version') != 'HTTP/1.1':
        http2_html = "<div class='subsection'><h3 class='subsection-title'>HTTP Protocol Info</h3><div class='info-grid'>"
        for key, value in http2_info.items():
            http2_html += f"""
            <div class="info-item">
                <div class="label">{escape(key.replace('_', ' ').title())}</div>
                <div class="value"><span class="badge badge-success">{escape(str(value))}</span></div>
            </div>
            """
        http2_html += "</div></div>"

    # Security headers analysis
    security_headers = headers_data.get('security_headers', {})
    security_html = ""
    if security_headers:
        security_html = "<div class='subsection'><h3 class='subsection-title'>Security Headers Analysis</h3><div class='info-grid'>"
        for key, value in security_headers.items():
            badge_class = "badge-success" if value else "badge-danger"
            security_html += f"""
            <div class="info-item">
                <div class="label">{escape(key.replace('_', ' ').title())}</div>
                <div class="value"><span class="badge {badge_class}">{'✓ Present' if value else '✗ Missing'}</span></div>
            </div>
            """
        security_html += "</div></div>"

    html = f"""
    <div class="section">
        <h2 class="section-title">📋 HTTP Headers Analysis</h2>
        {all_headers_html}
        {csp_html}
        {cors_html}
        {http2_html}
        {security_html}
    </div>
    """
    return html


def _generate_title_section(data):
    """Generate page title section"""
    title = data.get('title')

    # Always show this section, even if title is empty
    title_content = escape(title) if title else "<span style='color: #666; font-style: italic;'>No title found (empty &lt;title&gt; tag)</span>"

    html = f"""
    <div class="section">
        <h2 class="section-title">📄 Page Title</h2>
        <div class="code-block">{title_content}</div>
    </div>
    """
    return html


def _generate_ports_section(data):
    """Generate open ports section"""
    ports_data = data.get('ports') or {}
    ports = ports_data.get('ports', [])

    if not ports:
        return ""

    rows = ""
    for port in ports:
        port_num = port.get('port', 'N/A')
        service = port.get('name', 'unknown')
        product = port.get('product') or ''
        version = port.get('version') or ''
        ostype = port.get('ostype') or ''
        confidence = port.get('confidence') or ''
        banner = port.get('banner') or ''

        # Build product info with CPE if available
        product_info = f"{escape(product)} {escape(version)}".strip()
        cpe_list = port.get('cpe', [])
        if cpe_list:
            product_info += f"<br><small style='color: #8b9dc3;'>CPE: {escape(cpe_list[0] if isinstance(cpe_list, list) else cpe_list)}</small>"

        # SSH fingerprints with detailed display
        ssh_fp = port.get('ssh_fingerprints')
        ssh_html = ""
        if ssh_fp:
            sha256_fps = ssh_fp.get('sha256', [])
            md5_fps = ssh_fp.get('md5', [])
            ssh_html = "<br><div style='margin-top: 8px; padding: 8px; background: #1e1e2e; border-radius: 4px;'>"
            ssh_html += "<strong style='color: #667eea;'>🔑 SSH Fingerprints:</strong><br>"
            if sha256_fps:
                for fp in sha256_fps:
                    ssh_html += f"<small>SHA256: <code>{escape(fp)}</code></small><br>"
            if md5_fps:
                for fp in md5_fps:
                    ssh_html += f"<small>MD5: <code>{escape(fp)}</code></small><br>"
            ssh_html += "</div>"

        # Banner info
        banner_html = ""
        if banner:
            banner_html = f"<br><div style='margin-top: 8px;'><strong>Banner:</strong><br><code style='background: #1e1e2e; padding: 4px; border-radius: 2px;'>{escape(banner[:200])}</code></div>"

        rows += f"""
        <tr>
            <td><strong style='color: #667eea; font-size: 1.1em;'>{escape(str(port_num))}</strong></td>
            <td><span class="badge badge-success">{escape(service)}</span></td>
            <td>{product_info}</td>
            <td>{escape(ostype) if ostype else '-'}</td>
            <td>
                {f'<span class="badge badge-info">Confidence: {escape(confidence)}</span>' if confidence else ''}
                {banner_html}
                {ssh_html}
            </td>
        </tr>
        """

    html = f"""
    <div class="section">
        <h2 class="section-title">🔌 Open Ports & Services</h2>
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
            Nmap scan completed in {ports_data.get('time', 'N/A')} seconds
        </div>
    </div>
    """
    return html


def _generate_certificate_section(data):
    """Generate SSL/TLS certificate section"""
    cert = data.get('certificate')

    if not cert:
        return ""

    # Get all certificate fields dynamically
    cert_fields = []
    important_fields = ['CN', 'O', 'OU', 'L', 'ST', 'C', 'issuer', 'notBefore', 'notAfter', 'serialNumber']
    field_labels = {
        'CN': 'Common Name (CN)',
        'O': 'Organization (O)',
        'OU': 'Organizational Unit (OU)',
        'L': 'Locality (L)',
        'ST': 'State/Province (ST)',
        'C': 'Country (C)',
        'issuer': 'Issuer',
        'notBefore': 'Valid From',
        'notAfter': 'Valid Until',
        'serialNumber': 'Serial Number'
    }

    for field in important_fields:
        if field in cert and cert[field]:
            cert_fields.append((field_labels.get(field, field), cert[field]))

    # Add any other fields not in the important list
    for key, value in cert.items():
        if key not in important_fields and value:
            cert_fields.append((key, value))

    info_items = ""
    for label, value in cert_fields:
        info_items += f"""
        <div class="info-item">
            <div class="label">{escape(label)}</div>
            <div class="value"><code>{escape(str(value))}</code></div>
        </div>
        """

    html = f"""
    <div class="section">
        <h2 class="section-title">🔒 SSL/TLS Certificate</h2>
        <div class="info-grid">
            {info_items}
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

    # JARM active fingerprint
    jarm_html = ""
    if tls.get('jarm'):
        jarm_html = f"""
        <div class="subsection">
            <h3 class="subsection-title">JARM Fingerprint</h3>
            <div class="info-item"><div class="value"><code>{escape(tls['jarm'])}</code></div></div>
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
        {jarm_html}
    </div>
    """
    return html


def _generate_favicon_section(data):
    """Generate favicon section"""
    favicon = data.get('favicon')

    if not favicon or not isinstance(favicon, dict):
        return ""

    html = f"""
    <div class="section">
        <h2 class="section-title">🎨 Favicon Analysis</h2>
        <div class="info-grid">
            <div class="info-item">
                <div class="label">MMH3 Hash</div>
                <div class="value"><code>{escape(str(favicon.get('mmh3', 'N/A')))}</code></div>
            </div>
            <div class="info-item">
                <div class="label">MD5 Hash</div>
                <div class="value"><code>{escape(str(favicon.get('md5', 'N/A')))}</code></div>
            </div>
            <div class="info-item">
                <div class="label">Location</div>
                <div class="value">{escape(str(favicon.get('location', 'N/A')))}</div>
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


def _generate_deanon_section(data):
    """Generate the ranked deanonymisation-candidates section"""
    candidates = data.get('deanon_candidates') or []
    if not candidates:
        return ""

    badge = {
        'CONFIRMED': 'badge-danger',
        'LIKELY': 'badge-warning',
        'WEAK': 'badge-info',
        'NO_MATCH': 'badge-success',
        'UNREACHABLE': 'badge-success',
    }

    rows = ""
    for c in candidates:
        conf = c.get('confirmation', {})
        verdict = conf.get('verdict', 'UNREACHABLE')
        matches = ', '.join(conf.get('matches', [])) or '-'
        rows += f"""
        <tr>
            <td><code>{escape(str(c.get('candidate', '')))}</code></td>
            <td><span class="badge {badge.get(verdict, 'badge-info')}">{escape(verdict)}</span></td>
            <td>{escape(str(c.get('category_count', 0)))}</td>
            <td>{escape(', '.join(c.get('categories', [])))}</td>
            <td>{escape(', '.join(c.get('sources', [])))}</td>
            <td>{escape(matches)}</td>
        </tr>
        """

    return f"""
    <div class="section">
        <h2 class="section-title">🎯 Deanonymization Candidates</h2>
        <p class="empty-state">Candidate clearnet origins fused from all pivots, ranked by
        corroborating selector categories and confirmed by fetching each over clearnet and
        diffing against the onion baseline.</p>
        <div class="table-container">
            <table>
                <thead><tr>
                    <th>Candidate</th><th>Verdict</th><th>Selectors</th>
                    <th>Categories</th><th>Sources</th><th>Baseline matches</th>
                </tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </div>
    """


def _generate_contentleak_section(data):
    """Generate content-leak & attribution section"""
    leak = data.get('contentleak', {})
    if not leak:
        return ""

    clearnet = leak.get('clearnet_resources', [])
    outbound = leak.get('outbound_hosts', [])
    onionloc = leak.get('onion_location', {})
    pgp_keys = leak.get('pgp_keys', [])
    emails = leak.get('emails', [])
    body_hash = leak.get('body_hash')

    if not (clearnet or outbound or onionloc or pgp_keys or emails or body_hash):
        return ""

    body = ""

    if clearnet:
        body += "<div class='subsection'><h3 class='subsection-title'>⚠️ Clearnet resources loaded by the page</h3>"
        body += "<div class='table-container'><table><thead><tr><th>Clearnet host</th><th>Element</th><th>URL</th></tr></thead><tbody>"
        for item in clearnet[:30]:
            body += (f"<tr><td><code>{escape(item.get('host', ''))}</code></td>"
                     f"<td>&lt;{escape(item.get('element', ''))} {escape(item.get('attribute', ''))}&gt;</td>"
                     f"<td><code>{escape(item.get('url', ''))}</code></td></tr>")
        body += "</tbody></table></div></div>"

    if onionloc.get('onion_location'):
        body += ("<div class='subsection'><h3 class='subsection-title'>Onion-Location header</h3>"
                 f"<div class='list-item'><code>{escape(onionloc['onion_location'])}</code></div></div>")
    if onionloc.get('canonical_links'):
        body += "<div class='subsection'><h3 class='subsection-title'>Canonical / alternate links</h3>"
        for canon in onionloc['canonical_links']:
            body += f"<div class='list-item'><code>{escape(canon)}</code></div>"
        body += "</div>"

    if pgp_keys:
        body += "<div class='subsection'><h3 class='subsection-title'>PGP public keys</h3>"
        for key in pgp_keys:
            body += f"<div class='list-item'>key id <code>{escape(key.get('id', ''))}</code></div>"
        body += "</div>"

    if emails:
        body += "<div class='subsection'><h3 class='subsection-title'>Contact e-mails</h3>"
        for email in emails[:30]:
            body += f"<div class='list-item'><code>{escape(email)}</code></div>"
        body += "</div>"

    if outbound:
        body += "<div class='subsection'><h3 class='subsection-title'>Outbound clearnet links</h3>"
        for host in outbound[:30]:
            body += f"<div class='list-item'><code>{escape(host)}</code></div>"
        body += "</div>"

    if body_hash:
        body += ("<div class='subsection'><h3 class='subsection-title'>Body content hash (pivot)</h3>"
                 f"<div class='info-item'><div class='label'>mmh3</div><div class='value'><code>{escape(str(body_hash.get('mmh3')))}</code></div></div>"
                 f"<div class='info-item'><div class='label'>md5</div><div class='value'><code>{escape(str(body_hash.get('md5')))}</code></div></div>"
                 f"<div class='info-item'><div class='label'>sha256</div><div class='value'><code>{escape(str(body_hash.get('sha256')))}</code></div></div></div>")

    html = f"""
    <div class="section">
        <h2 class="section-title">🕵️ Content Leaks & Attribution</h2>
        {body}
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
