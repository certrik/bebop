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
    zoomeye_data = requests.get('https://api.zoomeye.ai/user/info', headers={'API-KEY': zoomeye_authkey})
    requests_left = zoomeye_data.json()['quota']['Remaining-Query-Credit']
    print('############# ZoomEye')
    print('{} remaining credits'.format(requests_left))
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
if os.getenv('CENSYS_API_ID', None) != None and os.getenv('CENSYS_API_SECRET', None) != None:
    censys_authid = os.getenv('CENSYS_API_ID')
    censys_authsecret = os.getenv('CENSYS_API_SECRET')
    censys_data = requests.get('https://search.censys.io/api/v1/account', auth=(censys_authid, censys_authsecret))
    requests_used = censys_data.json()['quota']['used']
    requests_available = censys_data.json()['quota']['allowance']
    requests_left = requests_available - requests_used
    print('############## Censys')
    print('used {} of {} available queries for current month - {} remaining'.format(requests_used, requests_available, requests_left))
else:
    log.error('CENSYS_API_ID or CENSYS_API_SECRET missing')

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
