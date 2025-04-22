#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import re
from app.subprocessors import query_shodan, query_censys, query_zoomeye, query_fofa

logger = logging.getLogger('bebop')

common_headers = []
with open('common/headers.txt', 'r', encoding='utf-8') as common_headers_file:
    for line in common_headers_file:
        common_headers.append(line.strip())
    common_headers_file.close()

def main(requestobject, doshodan=False, docensys=False, dozoome=False, dofofa=False):
    """
    Process HTTP headers from a request
    """
    interesting_headers = []
    for header in requestobject.headers:
        if header.lower() in ['etag', 'server']:
            interesting_headers.append(header)
            logger.info(f"Found interesting header: {header}")
    
    if 'etag' in interesting_headers:
        etag = requestobject.headers['etag']
        if doshodan:
            query_shodan(f'http.headers.etag:"{etag}"')
        if docensys:
            query_censys(f'services.http.response.headers.etag:"{etag}"')
        if dozoome:
            query_zoomeye(f'header.etag:"{etag}"')
        if dofofa:
            query_fofa(f'header.etag="{etag}"')
    
    if 'server' in interesting_headers:
        server = requestobject.headers['server']
        if doshodan:
            query_shodan(f'http.headers.server:"{server}"')
        if docensys:
            query_censys(f'services.http.response.headers.server:"{server}"')
        if dozoome:
            query_zoomeye(f'header.server:"{server}"')
        if dofofa:
            query_fofa(f'header.server="{server}"')
    
    return interesting_headers
