#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import re
from bs4 import BeautifulSoup

logger = logging.getLogger('bebop')


def extract_google_analytics(html_content):
    """
    Extract Google Analytics tracking IDs (UA-XXXXX, G-XXXXX, GT-XXXXX)
    """
    tracking_ids = set()

    # Pattern for Universal Analytics (UA-XXXXX-XX)
    ua_pattern = r'UA-\d{4,10}-\d{1,4}'
    ua_ids = re.findall(ua_pattern, html_content)
    tracking_ids.update(ua_ids)

    # Pattern for Google Analytics 4 (G-XXXXXXXXXX)
    ga4_pattern = r'G-[A-Z0-9]{10,}'
    ga4_ids = re.findall(ga4_pattern, html_content)
    tracking_ids.update(ga4_ids)

    # Pattern for Google Tag (GT-XXXXXXXXX)
    gt_pattern = r'GT-[A-Z0-9]{7,}'
    gt_ids = re.findall(gt_pattern, html_content)
    tracking_ids.update(gt_ids)

    return list(tracking_ids)


def extract_google_tag_manager(html_content):
    """
    Extract Google Tag Manager IDs (GTM-XXXXXX)
    """
    gtm_pattern = r'GTM-[A-Z0-9]{4,8}'
    gtm_ids = re.findall(gtm_pattern, html_content)
    return list(set(gtm_ids))


def extract_facebook_pixel(html_content):
    """
    Extract Facebook Pixel IDs
    """
    fb_pattern = r'fbq\s*\(\s*[\'"]init[\'"]\s*,\s*[\'"](\d{15,16})[\'"]'
    fb_ids = re.findall(fb_pattern, html_content)

    # Alternative pattern
    fb_pattern2 = r'facebook\.com/tr\?id=(\d{15,16})'
    fb_ids2 = re.findall(fb_pattern2, html_content)

    return list(set(fb_ids + fb_ids2))


def extract_yandex_metrica(html_content):
    """
    Extract Yandex Metrica IDs
    """
    yandex_pattern = r'ym\s*\(\s*(\d{7,9})\s*,'
    yandex_ids = re.findall(yandex_pattern, html_content)

    # Alternative pattern
    yandex_pattern2 = r'metrika/tag\.js.*?id[=:](\d{7,9})'
    yandex_ids2 = re.findall(yandex_pattern2, html_content)

    return list(set(yandex_ids + yandex_ids2))


def extract_matomo_piwik(html_content):
    """
    Extract Matomo/Piwik site IDs and tracker URLs
    """
    findings = {}

    # Matomo site ID pattern
    site_id_pattern = r'_paq\.push\s*\(\s*\[\s*[\'"]setSiteId[\'"]\s*,\s*[\'"]?(\d+)[\'"]?\s*\]\s*\)'
    site_ids = re.findall(site_id_pattern, html_content)

    if site_ids:
        findings['site_ids'] = list(set(site_ids))

    # Matomo tracker URL pattern
    tracker_pattern = r'_paq\.push\s*\(\s*\[\s*[\'"]setTrackerUrl[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]'
    tracker_urls = re.findall(tracker_pattern, html_content)

    if tracker_urls:
        findings['tracker_urls'] = list(set(tracker_urls))

    return findings if findings else None


def extract_cloudflare_analytics(html_content):
    """
    Extract Cloudflare Web Analytics tokens
    """
    cf_pattern = r'cloudflareinsights\.com/cdn-cgi/rum\?token=([a-f0-9]{32,})'
    cf_tokens = re.findall(cf_pattern, html_content)

    # Alternative pattern
    cf_pattern2 = r'__cfBeacon\s*=\s*{[^}]*token[\'"]?\s*:\s*[\'"]([a-f0-9]{32,})[\'"]'
    cf_tokens2 = re.findall(cf_pattern2, html_content)

    return list(set(cf_tokens + cf_tokens2))


def extract_hotjar(html_content):
    """
    Extract Hotjar site IDs
    """
    hotjar_pattern = r'hotjar\.com/c/hotjar-(\d+)\.js'
    hotjar_ids = re.findall(hotjar_pattern, html_content)

    # Alternative pattern
    hotjar_pattern2 = r'hjid[\'"]?\s*:\s*(\d{6,8})'
    hotjar_ids2 = re.findall(hotjar_pattern2, html_content)

    return list(set(hotjar_ids + hotjar_ids2))


def extract_mixpanel(html_content):
    """
    Extract Mixpanel tokens
    """
    mixpanel_pattern = r'mixpanel\.init\s*\(\s*[\'"]([a-f0-9]{32})[\'"]'
    mixpanel_tokens = re.findall(mixpanel_pattern, html_content)
    return list(set(mixpanel_tokens))


def extract_segment(html_content):
    """
    Extract Segment write keys
    """
    segment_pattern = r'analytics\.load\s*\(\s*[\'"]([a-zA-Z0-9]{20,})[\'"]'
    segment_keys = re.findall(segment_pattern, html_content)
    return list(set(segment_keys))


def extract_amplitude(html_content):
    """
    Extract Amplitude API keys
    """
    amplitude_pattern = r'amplitude\.getInstance\(\)\.init\s*\(\s*[\'"]([a-f0-9]{32})[\'"]'
    amplitude_keys = re.findall(amplitude_pattern, html_content)
    return list(set(amplitude_keys))


def extract_heap_analytics(html_content):
    """
    Extract Heap Analytics IDs
    """
    heap_pattern = r'heap\.load\s*\(\s*[\'"](\d{10,12})[\'"]'
    heap_ids = re.findall(heap_pattern, html_content)
    return list(set(heap_ids))


def extract_adsense(html_content):
    """
    Extract Google AdSense publisher IDs
    """
    adsense_pattern = r'google_ad_client\s*=\s*[\'"]ca-pub-(\d{16})[\'"]'
    adsense_ids = re.findall(adsense_pattern, html_content)

    # Alternative pattern
    adsense_pattern2 = r'pagead2\.googlesyndication\.com.*?client=ca-pub-(\d{16})'
    adsense_ids2 = re.findall(adsense_pattern2, html_content)

    return list(set(adsense_ids + adsense_ids2))


def search_tracking_id(tracking_id, platform):
    """
    Search for tracking ID across the web using PublicWWW-like approach
    Log the tracking ID for manual investigation
    """
    logger.info(f"=== {platform} Tracking ID Found: {tracking_id} ===")
    logger.info(f"Manual search recommended:")
    logger.info(f"  - Google: '{tracking_id}'")
    logger.info(f"  - PublicWWW: https://publicwww.com/websites/%22{tracking_id}%22/")
    logger.info(f"  - BuiltWith: https://builtwith.com/?{tracking_id}")


def main(requestobject):
    """
    Extract all analytics and tracking codes from webpage
    """
    html_content = requestobject.text
    findings = {}

    logger.info("Analyzing page for tracking and analytics codes...")

    # Google Analytics
    ga_ids = extract_google_analytics(html_content)
    if ga_ids:
        findings['google_analytics'] = ga_ids
        for ga_id in ga_ids:
            logger.info(f"Google Analytics ID found: {ga_id}")
            search_tracking_id(ga_id, "Google Analytics")

    # Google Tag Manager
    gtm_ids = extract_google_tag_manager(html_content)
    if gtm_ids:
        findings['google_tag_manager'] = gtm_ids
        for gtm_id in gtm_ids:
            logger.info(f"Google Tag Manager ID found: {gtm_id}")
            search_tracking_id(gtm_id, "Google Tag Manager")

    # Facebook Pixel
    fb_ids = extract_facebook_pixel(html_content)
    if fb_ids:
        findings['facebook_pixel'] = fb_ids
        for fb_id in fb_ids:
            logger.info(f"Facebook Pixel ID found: {fb_id}")
            search_tracking_id(fb_id, "Facebook Pixel")

    # Yandex Metrica
    yandex_ids = extract_yandex_metrica(html_content)
    if yandex_ids:
        findings['yandex_metrica'] = yandex_ids
        for yandex_id in yandex_ids:
            logger.info(f"Yandex Metrica ID found: {yandex_id}")
            search_tracking_id(yandex_id, "Yandex Metrica")

    # Matomo/Piwik
    matomo = extract_matomo_piwik(html_content)
    if matomo:
        findings['matomo'] = matomo
        if 'site_ids' in matomo:
            for site_id in matomo['site_ids']:
                logger.info(f"Matomo Site ID found: {site_id}")
        if 'tracker_urls' in matomo:
            for url in matomo['tracker_urls']:
                logger.info(f"Matomo Tracker URL found: {url}")
                # Extract domain from tracker URL for further investigation
                import re
                domain_match = re.search(r'https?://([^/]+)', url)
                if domain_match:
                    logger.info(f"  -> Tracker domain: {domain_match.group(1)}")

    # Cloudflare Analytics
    cf_tokens = extract_cloudflare_analytics(html_content)
    if cf_tokens:
        findings['cloudflare_analytics'] = cf_tokens
        for token in cf_tokens:
            logger.info(f"Cloudflare Web Analytics token found: {token}")

    # Hotjar
    hotjar_ids = extract_hotjar(html_content)
    if hotjar_ids:
        findings['hotjar'] = hotjar_ids
        for hj_id in hotjar_ids:
            logger.info(f"Hotjar ID found: {hj_id}")
            search_tracking_id(hj_id, "Hotjar")

    # Mixpanel
    mixpanel_tokens = extract_mixpanel(html_content)
    if mixpanel_tokens:
        findings['mixpanel'] = mixpanel_tokens
        for token in mixpanel_tokens:
            logger.info(f"Mixpanel token found: {token}")

    # Segment
    segment_keys = extract_segment(html_content)
    if segment_keys:
        findings['segment'] = segment_keys
        for key in segment_keys:
            logger.info(f"Segment write key found: {key}")

    # Amplitude
    amplitude_keys = extract_amplitude(html_content)
    if amplitude_keys:
        findings['amplitude'] = amplitude_keys
        for key in amplitude_keys:
            logger.info(f"Amplitude API key found: {key}")

    # Heap Analytics
    heap_ids = extract_heap_analytics(html_content)
    if heap_ids:
        findings['heap'] = heap_ids
        for heap_id in heap_ids:
            logger.info(f"Heap Analytics ID found: {heap_id}")

    # Google AdSense
    adsense_ids = extract_adsense(html_content)
    if adsense_ids:
        findings['google_adsense'] = adsense_ids
        for adsense_id in adsense_ids:
            logger.info(f"Google AdSense Publisher ID found: ca-pub-{adsense_id}")
            search_tracking_id(f"ca-pub-{adsense_id}", "Google AdSense")

    if not findings:
        logger.info("No analytics or tracking codes found")

    return findings
