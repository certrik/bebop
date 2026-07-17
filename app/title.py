#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import warnings
from bs4 import BeautifulSoup

from app.subprocessors import query_shodan, query_censys, query_zoomeye, query_fofa, query_modat

log = logging.getLogger(__name__)
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

common_titles = []
with open('common/http-titles.txt', 'r', encoding='utf-8') as common_titles_file:
    for line in common_titles_file:
        common_titles.append(line.strip())
    common_titles_file.close()

def main(requestobject, doshodan=True, docensys=True, dozoome=True, dofofa=True, domodat=True):
    soup = BeautifulSoup(requestobject.text, 'html.parser')
    title = soup.find('title')
    if title is not None:
        log.info('title: %s', title.text)
        if title.text not in common_titles and len(title.text) > 0:
            if doshodan:
                query_shodan('http.title:"' + title.text + '"')
            if docensys:
                # Platform v3: the page title lives on the web dataset.
                querystr = 'web.endpoints.http.html_title="' + title.text + '"'
                query_censys(querystr)
            if dozoome:
                query_zoomeye('title:"' + title.text + '"')
            if dofofa:
                query_fofa('title=' + str(title.text))
            if domodat:
                query_modat('web.title ~ "' + title.text + '"')
        return title.text
    log.warning('failed to extract title from %s', requestobject.url)
    return None
