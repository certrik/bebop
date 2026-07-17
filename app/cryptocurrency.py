#!/usr/bin/env python3
import re
import hashlib
import logging
import requests
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

rex = {
    'btc': re.compile(r'(bc1[a-z0-9]{25,87})|(([13])[A-HJ-NP-Za-km-z1-9]{25,34}(?![A-Za-z0-9]))'),
    'xmr': re.compile(r'([0-9AB]{1})([0-9a-zA-Z]{93})'),
    'eth': re.compile(r'0x[a-fA-F0-9]{40}')
}

_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def _b58check_valid(addr):
    '''Validate a legacy (1.../3...) base58check Bitcoin address by its checksum.
    This is what rejects hex-looking false matches that pass the regex.'''
    try:
        num = 0
        for ch in addr:
            num = num * 58 + _B58.index(ch)
    except ValueError:
        return False
    # account for leading '1's (each maps to a 0x00 byte)
    pad = len(addr) - len(addr.lstrip('1'))
    raw = b'\x00' * pad + num.to_bytes((num.bit_length() + 7) // 8, 'big')
    if len(raw) != 25:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


def _bech32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_valid(addr):
    '''Validate a bech32/bech32m (bc1...) address by its checksum.'''
    addr = addr.lower()
    pos = addr.rfind('1')
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return False
    hrp, data = addr[:pos], []
    for ch in addr[pos + 1:]:
        d = _BECH32.find(ch)
        if d == -1:
            return False
        data.append(d)
    expanded = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    const = _bech32_polymod(expanded + data)
    return const == 1 or const == 0x2bc830a3  # bech32 (v0) or bech32m (v1+)


def is_valid_btc(addr):
    if addr.startswith('bc1'):
        return _bech32_valid(addr)
    return _b58check_valid(addr)


def getwallet_data(wallet, chain='btc'):
    url = 'https://api.blockcypher.com/v1/%s/main/addrs/%s/balance' % (chain, wallet)
    try:
        data = requests.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        log.warning('%s: request failed for %s: %s', chain, wallet, e)
        return None
    if data.status_code == 200:
        bal = data.json()['final_balance']
        log.info('found %s wallet with balance %s (%s)', chain, bal, wallet)
        return data.json()
    if data.status_code == 429:
        log.warning('%s: blockcypher rate limit (429) - skipping lookup for %s', chain, wallet)
    else:
        log.debug('%s: no data for %s (status %s)', chain, wallet, data.status_code)
    return None

def main(sitesource):
    log.debug('searching for cryptocurrency wallets')
    findings = {key: [] for key in rex.keys()}
    for currency, pattern in rex.items():
        for match in re.finditer(pattern, sitesource):
            log.debug('found a potential %s wallet: %s', currency, match.group())
            findings[currency].append(match.group())
    for currency, values in findings.items():
        findings[currency] = list(set(values))
        for value in findings[currency]:
            log.debug('found a potential %s wallet: %s', currency, value)
            if currency == 'btc':
                # checksum-validate before hitting blockcypher so hex-looking
                # false matches don't generate noise (and needless rate-limited
                # API calls)
                if is_valid_btc(value):
                    getwallet_data(value)
                else:
                    log.debug('btc: %s failed checksum validation, skipping false match', value)
            elif currency == 'eth':
                getwallet_data(value, 'eth')
            else:
                log.info('found suspected %s wallet: %s', currency, value)
    if len(findings['btc']) == 0:
        log.debug('no btc wallets found')
    if len(findings['eth']) == 0:
        log.debug('no eth wallets found')
    if len(findings['xmr']) == 0:
        log.debug('no xmr wallets found')
    return findings

def walletexplorer_inspect_and_pivot(address):
    walletid = ""
    addresses = []
    pageaddr = requests.get(f"https://www.walletexplorer.com/address/{address}", timeout=10)
    if pageaddr.text.find(f"Address {address} not found") > -1:
        log.warning('address %s not found, likely a false match', address)
        return walletid, addresses
    soup = BeautifulSoup(pageaddr.text, 'html.parser')
    linkwallet = soup.find("div", {"class": "walletnote"}).find('a').get('href')
    walletid =  linkwallet.split("/")
    if(len(walletid)>0):
        urlwalletaddress = f"https://www.walletexplorer.com/wallet/{walletid[2]}/addresses"
        walletaddr = requests.get(urlwalletaddress, timeout=10)
        soup = BeautifulSoup(walletaddr.text, 'html.parser')
        addresstable = soup.find("table")
        trs = addresstable.find_all('tr')
        first = True
        for tr in trs:
            if not first:
                pivotaddress = tr.find("a").get("href").replace("/address/","")
                if pivotaddress != address:
                    addresses.append(pivotaddress)
            first = False
    return walletid, addresses

#getwallet_data('1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX', 'btc')
#getwallet_data('0x00000000219ab540356cbb839cbe05303d7705fa', 'eth')
#walletexplorer_inspect_and_pivot('bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6')
