#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import json
import requests
import logging

log = logging.getLogger(__name__)

# ZoomEye
if os.getenv('ZOOMEYE_API_KEY', None) != None:
    zoomeye_authkey = os.getenv('ZOOMEYE_API_KEY')
    # Legacy /user/info was retired with the v2 API rollout.
    zoomeye_data = requests.get('https://api.zoomeye.ai/v2/userinfo', headers={'API-KEY': zoomeye_authkey})
    subscription = zoomeye_data.json().get('data', {}).get('subscription', {})
    print('############# ZoomEye')
    print('{} free points, {} paid points remaining'.format(
        subscription.get('points'), subscription.get('zoomeye_points')))
else:
    log.error('ZOOMEYE_API_KEY missing')

# FOFA
if os.getenv('FOFA_API_KEY', None) != None:
    fofa_authkey = os.getenv('FOFA_API_KEY')
    fofa_data = requests.get('https://fofa.info/api/v1/info/my', params={'key': fofa_authkey})
    fofa_json = fofa_data.json()
    print('################ fofa')
    print('coins: {}'.format(fofa_json['fofa_coin']))
    print('points: {}'.format(fofa_json['fofa_point']))
    print('remaining queries: {}'.format(fofa_json['remaining_query']))
    print('remaining data: {}'.format(fofa_json['remaining_data']))
else:
    log.error('FOFA_API_KEY missing')

# Shodan
if os.getenv('SHODAN_API_KEY', None) != None:
    shodan_authkey = os.getenv('SHODAN_API_KEY')
    shodan_data = requests.get('https://api.shodan.io/account/profile?key=' + shodan_authkey)
    requests_left = shodan_data.json()['query_credits']
    print('############## Shodan')
    print('{} query credits remaining for current month'.format(requests_left))
else:
    log.error('SHODAN_API_KEY missing')

# Censys
# The legacy Search account/quota endpoint (search.censys.io/api/v1/account)
# was retired with the migration to the Censys Platform. Platform usage is
# tracked per organization in the web console rather than through a public
# quota endpoint, so we only confirm the credentials are present here.
if os.getenv('CENSYS_PERSONAL_ACCESS_TOKEN', None) != None and os.getenv('CENSYS_ORGANIZATION_ID', None) != None:
    print('############## Censys')
    print('Platform credentials configured for organization {} - view remaining credits at https://platform.censys.io'.format(
        os.getenv('CENSYS_ORGANIZATION_ID')))
else:
    log.error('CENSYS_PERSONAL_ACCESS_TOKEN or CENSYS_ORGANIZATION_ID missing')

# SecurityTrails
if os.getenv('SECURITYTRAILS_API_KEY', None) != None:
    securitytrails_authkey = os.getenv('SECURITYTRAILS_API_KEY')
    securitytrails_data = requests.get('https://api.securitytrails.com/v1/account/usage', headers={'APIKEY': securitytrails_authkey})
    requests_used = securitytrails_data.json()['usage']['current_month']['used']
    requests_available = securitytrails_data.json()['usage']['current_month']['limit']
    requests_left = requests_available - requests_used
    print('############## SecurityTrails')
    print('used {} of {} avail credits for current month'.format(requests_used, requests_available))
else:
    log.error('SECURITYTRAILS_API_KEY missing')

# urlscan.io
if os.getenv('URLSCAN_API_KEY', None) != None:
    urlscan_authkey = os.getenv('URLSCAN_API_KEY')
    urlscan_data = requests.get('https://urlscan.io/user/quotas', headers={'API-Key': urlscan_authkey})
    urlscan_json = urlscan_data.json()
    print('############## urlscan.io')
    print('used {} out of {} avail credits for current minute'.format(urlscan_json['minute']['used'], urlscan_json['minute']['limit']))
    print('used {} out of {} avail credits for current hour'.format(urlscan_json['hour']['used'], urlscan_json['hour']['limit']))
    print('used {} out of {} avail credits for today'.format(urlscan_json['day']['used'], urlscan_json['day']['limit']))
else:
    log.error('URLSCAN_API_KEY missing')

# VirusTotal
if os.getenv('VIRUSTOTAL_API_KEY', None) != None:
    virustotal_authkey = os.getenv('VIRUSTOTAL_API_KEY')
    virustotal_data = requests.get('https://www.virustotal.com/vtapi/v2/users/current', params={'apikey': virustotal_authkey})
    virustotal_json = virustotal_data.json()
    print('############## VirusTotal')
    print('used {} out of {} avail credits for today'.format(virustotal_json['requests_used']['today'], virustotal_json['requests_used']['day_limit']))
    print('used {} out of {} avail credits for current hour'.format(virustotal_json['requests_used']['hour'], virustotal_json['requests_used']['hour_limit']))
    print('used {} out of {} avail credits for current month'.format(virustotal_json['requests_used']['month'], virustotal_json['requests_used']['month_limit']))
else:
    log.error('VIRUSTOTAL_API_KEY missing')

# Validin
if os.getenv('VALIDIN_API_KEY', None) != None:
    validin_authkey = os.getenv('VALIDIN_API_KEY')
    validin_data = requests.get('https://app.validin.com/api/profile/usage',
                                headers={'Authorization': 'BEARER ' + validin_authkey})
    print('############## Validin')
    print(json.dumps(validin_data.json(), indent=2))
else:
    log.error('VALIDIN_API_KEY missing')

# Modat Magnify
if os.getenv('MODAT_API_KEY', None) != None:
    modat_authkey = os.getenv('MODAT_API_KEY')
    modat_data = requests.get('https://api.magnify.modat.io/search/quotas/v1',
                              headers={'Authorization': 'Bearer ' + modat_authkey})
    modat_json = modat_data.json()
    print('############## Modat Magnify')
    print('{} of {} searches remaining, {} of {} results remaining'.format(
        modat_json['remaining_search_quota'], modat_json['search_quota'],
        modat_json['remaining_results_quota'], modat_json['search_results_quota']))
else:
    log.error('MODAT_API_KEY missing')
