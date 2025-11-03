#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
builds nmap response
'''
import os
import json
import logging
import subprocess
import hashlib
import re

from app.utilities import gen_chainconfig

log = logging.getLogger(__name__)


def extract_ssh_fingerprints(hostkey_output):
    """
    Extract SSH fingerprints from nmap ssh-hostkey output
    Returns dictionary of fingerprint types and values
    """
    fingerprints = {
        'sha256': [],
        'md5': [],
        'keys': []
    }

    lines = hostkey_output.splitlines()

    for line in lines:
        line = line.strip()

        # Extract SHA256 fingerprints
        if 'SHA256:' in line:
            match = re.search(r'SHA256:([A-Za-z0-9+/=]+)', line)
            if match:
                fp = match.group(1)
                fingerprints['sha256'].append(fp)
                log.info(f"SSH SHA256 fingerprint: {fp}")

        # Extract MD5 fingerprints
        if 'MD5:' in line or re.match(r'[0-9a-f]{2}(:[0-9a-f]{2}){15}', line):
            match = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', line)
            if match:
                fp = match.group(1)
                fingerprints['md5'].append(fp)
                log.info(f"SSH MD5 fingerprint: {fp}")

        # Extract key types
        if any(ktype in line for ktype in ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-dss']):
            for ktype in ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-dss']:
                if ktype in line:
                    fingerprints['keys'].append(ktype)

    return fingerprints


def analyze_ssh_banner(banner):
    """
    Analyze SSH banner for custom modifications or interesting info
    """
    if not banner:
        return None

    analysis = {
        'raw_banner': banner,
        'is_custom': False,
        'software': None,
        'version': None
    }

    # Standard SSH banner format: SSH-2.0-Software_Version Comments
    match = re.match(r'SSH-([\d.]+)-(.+)', banner)
    if match:
        protocol_version = match.group(1)
        software_string = match.group(2).strip()

        analysis['protocol_version'] = protocol_version
        analysis['software'] = software_string

        # Check for common SSH servers
        common_servers = {
            'OpenSSH': r'OpenSSH_([\d.]+[a-z]?\d*)',
            'libssh': r'libssh[_-]([\d.]+)',
            'Dropbear': r'dropbear[_-]([\d.]+)',
            'PuTTY': r'PuTTY[_-]Release[_-]([\d.]+)',
            'WinSSHD': r'WinSSHD[_-]([\d.]+)',
            'Tectia': r'SSH\s+Tectia\s+Server\s+([\d.]+)',
        }

        for server_name, pattern in common_servers.items():
            server_match = re.search(pattern, software_string, re.IGNORECASE)
            if server_match:
                analysis['software'] = server_name
                analysis['version'] = server_match.group(1)
                log.info(f"SSH server identified: {server_name} {server_match.group(1)}")
                break

        # Check if banner has been customized (no recognizable software)
        if not analysis['version']:
            analysis['is_custom'] = True
            log.info(f"Custom SSH banner detected: {banner}")

    return analysis


def query_ssh_fingerprints(fingerprints, doshodan=True, docensys=True):
    """
    Query threat intelligence platforms for SSH fingerprints
    """
    try:
        from app.subprocessors import query_shodan, query_censys

        # Query SHA256 fingerprints
        for sha256_fp in fingerprints.get('sha256', []):
            if doshodan:
                query_shodan(f'ssh.hassh:"{sha256_fp}"')
            # Censys doesn't have direct SSH fingerprint search in same format

        # Query MD5 fingerprints
        for md5_fp in fingerprints.get('md5', []):
            if doshodan:
                # Shodan uses different format
                query_shodan(f'ssh.fingerprint:"{md5_fp}"')

    except Exception as e:
        log.error(f"Failed to query SSH fingerprints: {e}")


def portdata(port):
    log.info('found open port: %s', str(port['@portid']) + '/' + port['@protocol'])
    portinf = {
        'port': port['@portid'],
        'name': None,
        'product': None,
        'service': None,
        'ostype': None,
        'cpe': None,
        'banner': None,
        'hostprints': [],
        'shellauthmethods': [],
        'ssh_fingerprints': None,
        'ssh_banner_analysis': None
    }
    if '@name' in port['service']:
        portinf['name'] = port['service']['@name']
    if '@product' in port['service']:
        portinf['product'] = port['service']['@product']
    if '@conf' in port['service']:
        portinf['confidence'] = port['service']['@conf']
    if '@version' in port['service']:
        portinf['version'] = port['service']['@version']
    if '@ostype' in port['service']:
        portinf['ostype'] = port['service']['@ostype']
    if 'cpe' in port['service']:
        portinf['cpe'] = port['service']['cpe']

    # Track if this is an SSH port
    is_ssh_port = False

    if 'script' in port:
        scripts = port['script']
        if isinstance(scripts, dict):  # Convert single dict to list
            scripts = [scripts]
        if isinstance(scripts, list):  # Ensure it's iterable
            for script in scripts:
                try:
                    if isinstance(script, dict) and '@id' in script:
                        if script['@id'] == 'banner':
                            portinf['banner'] = script.get('@output', '')

                            # Analyze SSH banner if present
                            if portinf['banner'].startswith('SSH-'):
                                is_ssh_port = True
                                banner_analysis = analyze_ssh_banner(portinf['banner'])
                                if banner_analysis:
                                    portinf['ssh_banner_analysis'] = banner_analysis

                        elif script['@id'] == 'ssh-hostkey':
                            is_ssh_port = True
                            output = script.get('@output', '')

                            for line in output.splitlines():
                                if line and not line.isspace():
                                    portinf['hostprints'].append(line.strip())

                            # Extract and analyze SSH fingerprints
                            fingerprints = extract_ssh_fingerprints(output)
                            if any(fingerprints.values()):
                                portinf['ssh_fingerprints'] = fingerprints

                                # Query threat intelligence for SSH fingerprints
                                query_ssh_fingerprints(fingerprints)

                        elif script['@id'] == 'ssh-auth-methods':
                            output = script.get('@output', '')
                            if 'publickey' in output:
                                portinf['shellauthmethods'].append('publickey')
                            if 'password' in output:
                                portinf['shellauthmethods'].append('password')
                            if 'keyboard-interactive' in output:
                                portinf['shellauthmethods'].append('keyboard-interactive')

                except Exception as e:
                    log.debug('failed to parse script: %s', e)
                    log.debug('script data: %s', script)

    # Log SSH configuration summary
    if is_ssh_port:
        log.info(f"SSH port detected on {portinf['port']}")
        if portinf.get('shellauthmethods'):
            log.info(f"SSH auth methods: {', '.join(portinf['shellauthmethods'])}")

    return portinf

def main(fqdn, useragent, usetor=True, max_scanport=40):
    command='\
nmap -sT -PN -n -sV --open -oX - --top-ports %s \
--version-intensity 4 --script ssh-hostkey,ssh-auth-methods,banner \
--script-args http.useragent="%s",ssh_hostkey=sha256,md5 %s | xq' % (max_scanport, useragent, fqdn)
    if usetor:
        gen_chainconfig()
        command = 'proxychains4 -f ../proxychains.conf ' + command
    log.debug('commencing portscan on %s', fqdn)
    log.debug('command: %s', command)
    output = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
    scanout = json.loads(output.stdout)
    scanout['args'] = scanout['nmaprun']['@args']
    if 'host' not in scanout['nmaprun']:
        log.info('no open ports discovered?')
        return scanout
    portarr = scanout['nmaprun']['host']['ports']['port']
    log.debug(scanout['nmaprun']['@args'])
    if scanout['nmaprun']['host']['status']['@state'] == 'up':
        scanout['ports'] = []
        if isinstance(portarr, list):
            for port in portarr:
                pdata = portdata(port)
                log.info(pdata)
                scanout['ports'].append(pdata)
        else:
            pdata = portdata(portarr)
            log.info(pdata)
            scanout['ports'].append(pdata)
    else:
        log.info('no open ports discovered?')
        log.error(scanout)
    scanout['time'] = int(float(scanout['nmaprun']['runstats']['finished']['@elapsed']))
    log.debug(scanout)
    return scanout
