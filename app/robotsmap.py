#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from app.getpage import main as getpage_main

logger = logging.getLogger('bebop')


def parse_robots_txt(robots_content, base_url):
    """
    Parse robots.txt and extract interesting paths and directives
    """
    findings = {
        'disallowed_paths': [],
        'allowed_paths': [],
        'sitemaps': [],
        'crawl_delays': {},
        'interesting_comments': [],
        'user_agents': []
    }

    lines = robots_content.split('\n')
    current_agent = None

    for line in lines:
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Extract comments (might contain useful info)
        if line.startswith('#'):
            comment = line[1:].strip()
            if len(comment) > 5:  # Ignore short comments
                findings['interesting_comments'].append(comment)
                logger.debug(f"Comment found: {comment}")
            continue

        # Parse directive
        if ':' in line:
            directive, value = line.split(':', 1)
            directive = directive.strip().lower()
            value = value.strip()

            if directive == 'user-agent':
                current_agent = value
                if value not in findings['user_agents']:
                    findings['user_agents'].append(value)

            elif directive == 'disallow':
                if value and value != '/':
                    full_path = urljoin(base_url, value)
                    findings['disallowed_paths'].append({
                        'path': value,
                        'full_url': full_path,
                        'user_agent': current_agent
                    })
                    logger.info(f"Disallowed path found: {value}")

            elif directive == 'allow':
                if value:
                    full_path = urljoin(base_url, value)
                    findings['allowed_paths'].append({
                        'path': value,
                        'full_url': full_path,
                        'user_agent': current_agent
                    })
                    logger.info(f"Allowed path found: {value}")

            elif directive == 'sitemap':
                findings['sitemaps'].append(value)
                logger.info(f"Sitemap found: {value}")

            elif directive == 'crawl-delay':
                if current_agent:
                    findings['crawl_delays'][current_agent] = value

    return findings


def parse_sitemap_xml(sitemap_content, base_url):
    """
    Parse sitemap.xml and extract URLs
    """
    findings = {
        'urls': [],
        'sitemaps': [],  # For sitemap index files
        'errors': []
    }

    try:
        # Remove XML namespace to simplify parsing
        sitemap_content = sitemap_content.replace(' xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"', '')

        root = ET.fromstring(sitemap_content)

        # Check if it's a sitemap index
        if root.tag == 'sitemapindex':
            for sitemap in root.findall('sitemap'):
                loc = sitemap.find('loc')
                if loc is not None and loc.text:
                    findings['sitemaps'].append(loc.text)
                    logger.info(f"Sitemap index entry: {loc.text}")

        # Regular sitemap with URLs
        elif root.tag == 'urlset':
            for url in root.findall('url'):
                loc = url.find('loc')
                lastmod = url.find('lastmod')
                priority = url.find('priority')
                changefreq = url.find('changefreq')

                if loc is not None and loc.text:
                    url_data = {'loc': loc.text}

                    if lastmod is not None and lastmod.text:
                        url_data['lastmod'] = lastmod.text

                    if priority is not None and priority.text:
                        url_data['priority'] = priority.text

                    if changefreq is not None and changefreq.text:
                        url_data['changefreq'] = changefreq.text

                    findings['urls'].append(url_data)

            logger.info(f"Found {len(findings['urls'])} URLs in sitemap")

        # Look for interesting patterns in URLs
        if findings['urls']:
            admin_urls = [u for u in findings['urls'] if 'admin' in u['loc'].lower()]
            api_urls = [u for u in findings['urls'] if 'api' in u['loc'].lower()]
            login_urls = [u for u in findings['urls'] if 'login' in u['loc'].lower()]

            if admin_urls:
                logger.info(f"Found {len(admin_urls)} admin-related URLs in sitemap")
            if api_urls:
                logger.info(f"Found {len(api_urls)} API-related URLs in sitemap")
            if login_urls:
                logger.info(f"Found {len(login_urls)} login-related URLs in sitemap")

    except ET.ParseError as e:
        findings['errors'].append(f"XML parsing error: {str(e)}")
        logger.error(f"Failed to parse sitemap XML: {e}")
    except Exception as e:
        findings['errors'].append(f"Unexpected error: {str(e)}")
        logger.error(f"Error processing sitemap: {e}")

    return findings


def analyze_robots_patterns(robots_findings):
    """
    Analyze robots.txt findings for interesting patterns
    """
    insights = []

    # Check for admin/sensitive paths
    sensitive_keywords = ['admin', 'wp-admin', 'administrator', 'panel', 'dashboard',
                          'login', 'auth', 'api', 'private', 'secret', 'config',
                          'backup', 'dev', 'test', 'staging', 'internal']

    for disallowed in robots_findings.get('disallowed_paths', []):
        path = disallowed['path'].lower()
        for keyword in sensitive_keywords:
            if keyword in path:
                insights.append(f"Sensitive path disallowed: {disallowed['path']} (contains '{keyword}')")
                logger.info(f"Potentially sensitive path: {disallowed['path']}")
                break

    # Check for multiple user-agents (might indicate anti-bot measures)
    user_agents = robots_findings.get('user_agents', [])
    if len(user_agents) > 3:
        insights.append(f"Multiple user-agents defined ({len(user_agents)}) - custom bot handling")

    # Check crawl delays
    crawl_delays = robots_findings.get('crawl_delays', {})
    if crawl_delays:
        for agent, delay in crawl_delays.items():
            insights.append(f"Crawl delay set for {agent}: {delay} seconds")

    return insights


def main(base_url, usetor=True):
    """
    Analyze robots.txt and sitemap.xml for a given URL
    """
    findings = {
        'robots_txt': None,
        'sitemaps': [],
        'insights': []
    }

    # Fetch and analyze robots.txt
    robots_url = urljoin(base_url, '/robots.txt')
    logger.info(f"Fetching robots.txt from {robots_url}")

    robots_response = getpage_main(robots_url, usetor=usetor)

    if robots_response and robots_response.status_code == 200:
        logger.info("robots.txt found, analyzing...")
        robots_findings = parse_robots_txt(robots_response.text, base_url)
        findings['robots_txt'] = robots_findings

        # Analyze patterns
        insights = analyze_robots_patterns(robots_findings)
        findings['insights'].extend(insights)

        # Process sitemaps found in robots.txt
        for sitemap_url in robots_findings.get('sitemaps', []):
            logger.info(f"Fetching sitemap from robots.txt: {sitemap_url}")
            sitemap_response = getpage_main(sitemap_url, usetor=usetor)

            if sitemap_response and sitemap_response.status_code == 200:
                sitemap_data = parse_sitemap_xml(sitemap_response.text, base_url)
                findings['sitemaps'].append({
                    'url': sitemap_url,
                    'data': sitemap_data
                })

                # If it's a sitemap index, fetch individual sitemaps
                if sitemap_data.get('sitemaps'):
                    logger.info(f"Sitemap index found with {len(sitemap_data['sitemaps'])} sitemaps")
                    for sub_sitemap_url in sitemap_data['sitemaps'][:5]:  # Limit to first 5
                        logger.info(f"Fetching sub-sitemap: {sub_sitemap_url}")
                        sub_response = getpage_main(sub_sitemap_url, usetor=usetor)
                        if sub_response and sub_response.status_code == 200:
                            sub_data = parse_sitemap_xml(sub_response.text, base_url)
                            findings['sitemaps'].append({
                                'url': sub_sitemap_url,
                                'data': sub_data
                            })

    else:
        logger.info("robots.txt not found or not accessible")

    # Try standard sitemap.xml location if not found in robots.txt
    if not findings['sitemaps']:
        sitemap_url = urljoin(base_url, '/sitemap.xml')
        logger.info(f"Trying standard sitemap location: {sitemap_url}")
        sitemap_response = getpage_main(sitemap_url, usetor=usetor)

        if sitemap_response and sitemap_response.status_code == 200:
            logger.info("sitemap.xml found at standard location")
            sitemap_data = parse_sitemap_xml(sitemap_response.text, base_url)
            findings['sitemaps'].append({
                'url': sitemap_url,
                'data': sitemap_data
            })

    # Summary
    total_urls = sum(len(s['data'].get('urls', [])) for s in findings['sitemaps'])
    if total_urls > 0:
        logger.info(f"Total URLs discovered across all sitemaps: {total_urls}")

    if findings['robots_txt']:
        disallowed_count = len(findings['robots_txt'].get('disallowed_paths', []))
        if disallowed_count > 0:
            logger.info(f"Total disallowed paths in robots.txt: {disallowed_count}")

    return findings
