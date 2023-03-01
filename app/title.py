#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import warnings
from bs4 import BeautifulSoup

import shodansearch
import censyssearch

log = logging.getLogger(__name__)
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

common_titles = []
with open('common/http-titles.txt', 'r', encoding='utf-8') as common_titles_file:
    for line in common_titles_file:
        common_titles.append(line.strip())
    common_titles_file.close()

def main(requestobject, doshodan=True, docensys=True):
    if len(requestobject.text.splitlines()) == 1:
        log.error('single line response, not parsing')
        return None
    soup = BeautifulSoup(requestobject.text, 'html.parser')
    title = soup.find('title')
    if title is not None:
        log.info('title: %s', title.text)
        if doshodan and title.text not in common_titles:
            shodansearch.query('http.title:"' + title.text + '"')
        if docensys and title.text not in common_titles:
            querystr = 'services.http.response.html_title:"' + title.text + '"'
            censyssearch.query(querystr)
        return title.text
    log.error('no title found on page')
    #log.debug('page source: %s', requestobject.text)
    return None
