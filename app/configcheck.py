#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import uuid
import logging
import asyncio
from aiohttp import ClientSession, ClientTimeout
from aiohttp_socks import ProxyConnector

log = logging.getLogger(__name__)

from app.title import main as title_main
from app.utilities import getsocks, useragentstr

async def is_catch_all(session, location, attempts=3):
    for _ in range(attempts):
        random_path = "/" + str(uuid.uuid4())
        uri = location + random_path
        try:
            log.debug('scanning %s as for catch-all validation', uri)
            # ssl=False: onion/origin services routinely present self-signed
            # certs; verifying would fail every HTTPS path check.
            async with session.get(uri, timeout=10, ssl=False) as response:
                if response.status != 200:  
                    return False
        except Exception as e:
            log.error('error fetching %s - %s', uri, e)
            return False
    return True

interesting_paths = [
    {'uri': '/server-status', 'code': 200, 'text': 'Apache'},
    {'uri': '/install/index.php', 'code': 200, 'text': 'Installation Wizard'},
    {'uri': '/server-info', 'code': 200, 'text': 'Apache'},
    {'uri': '/wp-login.php', 'code': 200, 'text': 'login'},
    {'uri': '/xmlrpc.php', 'code': 405, 'text': 'XML-RPC server accepts POST requests only'},
    {'uri': '/phpinfo.php', 'code': 200, 'text': 'This program makes use of the Zend'},
    {'uri': '/cpanel', 'code': 200, 'text': 'cPanel, Inc'},
    {'uri': '/phpmyadmin/', 'code': 200, 'text': 'Welcome to phpMyAdmin'},
    {'uri': '/phpsysinfo/', 'code': 200, 'text': 'phpSysInfo'},
    {'uri': '/adminer/', 'code': 200, 'text': 'Adminer'},
    {'uri': '/joomla', 'code': 200, 'text': 'Joomla'},
    {'uri': '/drupal', 'code': 200, 'text': 'Drupal'},
    {'uri': '/jenkins', 'code': 200, 'text': 'Jenkins'},
    {'uri': '/grafana', 'code': 200, 'text': 'Grafana'},
    {'uri': '/kibana', 'code': 200, 'text': 'Kibana'},
    {'uri': '/.well-known/security.txt', 'code': 200, 'text': 'Contact'},
    {'uri': '/manager/html', 'code': 200, 'text': 'Apache Tomcat'},
    {'uri': '/robots.txt', 'code': 200, 'text': None},
    {'uri': '/sitemap.xml', 'code': 200, 'text': None},
    {'uri': '/admin', 'code': 200, 'text': None},
    {'uri': '/administrator', 'code': 200, 'text': None},
    {'uri': '/wp-admin', 'code': 200, 'text': None},
    {'uri': '/wp-admin/admin-ajax.php', 'code': 200, 'text': None},
    {'uri': '/.git', 'code': 200, 'text': None},
    {'uri': '/.env', 'code': 200, 'text': None},
    {'uri': '/WEB-INF/web.xml', 'code': 200, 'text': None},
    {'uri': '/config.php', 'code': 200, 'text': None},
    {'uri': '/backup.sql', 'code': 200, 'text': None},
    {'uri': '/backup.tar.gz', 'code': 200, 'text': None},
    {'uri': '/wp-config.php.bak', 'code': 200, 'text': None},
    {'uri': '/install.php', 'code': 200, 'text': None},
    {'uri': '/readme.html', 'code': 200, 'text': None},
    {'uri': '/CHANGELOG.txt', 'code': 200, 'text': None},
    {'uri': '/LICENSE.txt', 'code': 200, 'text': None},
    {'uri': '/api/v1/users', 'code': 200, 'text': None},
    {'uri': '/api/v1/tokens', 'code': 200, 'text': None},
    {'uri': '/api-docs', 'code': 200, 'text': None},
    {'uri': '/test.php', 'code': 200, 'text': None},
    {'uri': '/debug.php', 'code': 200, 'text': None},
    {'uri': '/info.php', 'code': 200, 'text': None},
    {'uri': '/uploads', 'code': 200, 'text': None},
    {'uri': '/files', 'code': 200, 'text': None},
    {'uri': '/media', 'code': 200, 'text': None},
    {'uri': '/500.html', 'code': 200, 'text': None},
    {'uri': '/.htaccess', 'code': 200, 'text': None},
    {'uri': '/.htpasswd', 'code': 200, 'text': None},
    {'uri': '/.svn', 'code': 200, 'text': None},
    {'uri': '/.git/config', 'code': 200, 'text': None},
    {'uri': '/README.md', 'code': 200, 'text': None},
    {'uri': '/.DS_Store', 'code': 200, 'text': None},
    {'uri': '/swagger-ui.html', 'code': 200, 'text': None},
    {'uri': '/console', 'code': 200, 'text': None},
    {'uri': '/.dockerenv', 'code': 200, 'text': None},
    {'uri': '/.gitlab-ci.yml', 'code': 200, 'text': None},
    {'uri': '/.travis.yml', 'code': 200, 'text': None},
    {'uri': '/.circleci/config.yml', 'code': 200, 'text': None},
    {'uri': '/error_log', 'code': 200, 'text': None},
    {'uri': '/access_log', 'code': 200, 'text': None},
    {'uri': '/modx', 'code': 200, 'text': 'MODX'},
    {'uri': '/typo3', 'code': 200, 'text': 'TYPO3'},
    {'uri': '/symfony', 'code': 200, 'text': 'Symfony'},
    {'uri': '/swagger', 'code': 200, 'text': 'Swagger'},
    {'uri': '/redmine', 'code': 200, 'text': 'Redmine'},
    {'uri': '/gitweb', 'code': 200, 'text': 'GitWeb'},
    {'uri': '/git', 'code': 200, 'text': 'GitLab'},
    {'uri': '/composer.lock', 'code': 200, 'text': None},
    {'uri': '/package-lock.json', 'code': 200, 'text': None},
    {'uri': '/yarn.lock', 'code': 200, 'text': None},
    {'uri': '/.TemporaryItems', 'code': 200, 'text': None},
    {'uri': '/.access.php', 'code': 200, 'text': None},
    {'uri': '/.buildpath', 'code': 200, 'text': None},
    {'uri': '/.env.example', 'code': 200, 'text': None},
    {'uri': '/.ftpquota', 'code': 200, 'text': None},
    {'uri': '/.gitattributes', 'code': 200, 'text': None},
    {'uri': '/.github', 'code': 200, 'text': None},
    {'uri': '/.gitignore', 'code': 200, 'text': None},
    {'uri': '/.hg', 'code': 200, 'text': None},
    {'uri': '/.hgignore', 'code': 200, 'text': None},
    {'uri': '/.htaccess', 'code': 200, 'text': None},
    {'uri': '/.htpasswd', 'code': 200, 'text': None},
    {'uri': '/.htpasswds', 'code': 200, 'text': None},
    {'uri': '/.idea', 'code': 200, 'text': None},
    {'uri': '/.localized', 'code': 200, 'text': None},
    {'uri': '/.platform', 'code': 200, 'text': None},
    {'uri': '/.project', 'code': 200, 'text': None},
    {'uri': '/.qidb', 'code': 200, 'text': None},
    {'uri': '/.quarantine', 'code': 200, 'text': None},
    {'uri': '/.sass-cache', 'code': 200, 'text': None},
    {'uri': '/.section.php', 'code': 200, 'text': None},
    {'uri': '/.settings', 'code': 200, 'text': None},
    {'uri': '/.smileys', 'code': 200, 'text': None},
    {'uri': '/.styleci.yml', 'code': 200, 'text': None},
    {'uri': '/.tmb', 'code': 200, 'text': None},
    {'uri': '/.top.menu.php', 'code': 200, 'text': None},
    {'uri': '/.user.ini', 'code': 200, 'text': None},
    {'uri': '/.vscode', 'code': 200, 'text': None},
    {'uri': '/.well-known', 'code': 200, 'text': None},
    {'uri': '/.ini', 'code': 200, 'text': None},

    # --- origin-IP / internal-address leaks (highest value for deanon) ---
    # These endpoints print the server's own address, internal hostnames, or
    # backend topology - i.e. exactly what a hidden service is trying to hide.
    {'uri': '/server-status?auto', 'code': 200, 'text': 'Total Accesses'},   # Apache mod_status (machine-readable)
    {'uri': '/nginx_status', 'code': 200, 'text': 'Active connections'},     # nginx stub_status
    {'uri': '/stub_status', 'code': 200, 'text': 'Active connections'},
    {'uri': '/status?full', 'code': 200, 'text': 'accepted conn'},           # PHP-FPM status
    {'uri': '/fpm-status', 'code': 200, 'text': 'accepted conn'},
    {'uri': '/php-fpm-status', 'code': 200, 'text': 'accepted conn'},
    {'uri': '/metrics', 'code': 200, 'text': '# TYPE'},                      # Prometheus exposition (instance= labels leak IP:port)
    {'uri': '/debug/vars', 'code': 200, 'text': 'cmdline'},                  # Go expvar (cmdline / memstats)
    {'uri': '/debug/pprof/', 'code': 200, 'text': 'profiles'},              # Go net/http/pprof index
    {'uri': '/_profiler/', 'code': 200, 'text': 'Profiler'},                # Symfony profiler (SERVER_ADDR = origin IP)
    {'uri': '/app_dev.php', 'code': 200, 'text': None},                     # Symfony dev front controller
    {'uri': '/actuator', 'code': 200, 'text': '_links'},                    # Spring Boot Actuator index
    {'uri': '/actuator/health', 'code': 200, 'text': 'status'},
    {'uri': '/actuator/env', 'code': 200, 'text': 'propertySources'},       # leaks env vars, hostnames
    {'uri': '/actuator/configprops', 'code': 200, 'text': 'contexts'},
    {'uri': '/actuator/mappings', 'code': 200, 'text': 'dispatcherServlet'},
    {'uri': '/actuator/heapdump', 'code': 200, 'text': None},               # full heap - credentials & addresses
    {'uri': '/telescope/requests', 'code': 200, 'text': 'Telescope'},       # Laravel Telescope
    {'uri': '/horizon/api/stats', 'code': 200, 'text': None},              # Laravel Horizon
    {'uri': '/_ignition/health-check', 'code': 200, 'text': 'can_execute_commands'},  # Laravel Ignition

    # --- version-control / attribution leaks (who runs it) ---
    {'uri': '/.git/HEAD', 'code': 200, 'text': 'ref:'},
    {'uri': '/.git/logs/HEAD', 'code': 200, 'text': None},                 # commit author names + e-mails
    {'uri': '/.svn/entries', 'code': 200, 'text': None},
    {'uri': '/.svn/wc.db', 'code': 200, 'text': None},
    {'uri': '/.hg/store', 'code': 200, 'text': None},
    {'uri': '/.bzr/branch/last-revision', 'code': 200, 'text': None},
    {'uri': '/humans.txt', 'code': 200, 'text': None},                     # frequently names the operators

    # --- config / secret files (connection strings, keys, backend hosts) ---
    {'uri': '/.env.local', 'code': 200, 'text': None},
    {'uri': '/.env.production', 'code': 200, 'text': None},
    {'uri': '/.env.dev', 'code': 200, 'text': None},
    {'uri': '/.env.backup', 'code': 200, 'text': None},
    {'uri': '/appsettings.json', 'code': 200, 'text': 'ConnectionStrings'}, # .NET
    {'uri': '/web.config', 'code': 200, 'text': 'configuration'},
    {'uri': '/docker-compose.yml', 'code': 200, 'text': 'services'},
    {'uri': '/docker-compose.yaml', 'code': 200, 'text': 'services'},
    {'uri': '/config.json', 'code': 200, 'text': None},
    {'uri': '/config.yml', 'code': 200, 'text': None},
    {'uri': '/settings.py', 'code': 200, 'text': None},
    {'uri': '/wp-config.php.save', 'code': 200, 'text': None},
    {'uri': '/wp-config.php.orig', 'code': 200, 'text': None},
    {'uri': '/wp-config.php~', 'code': 200, 'text': None},
    {'uri': '/.aws/credentials', 'code': 200, 'text': None},
    {'uri': '/.ssh/id_rsa', 'code': 200, 'text': None},
    {'uri': '/.npmrc', 'code': 200, 'text': None},
    {'uri': '/.netrc', 'code': 200, 'text': None},
    {'uri': '/.kube/config', 'code': 200, 'text': None},

    # --- APIs / dashboards that enumerate users or expose infrastructure ---
    {'uri': '/wp-json/wp/v2/users', 'code': 200, 'text': 'slug'},           # WordPress author enumeration
    {'uri': '/?rest_route=/wp/v2/users', 'code': 200, 'text': 'slug'},
    {'uri': '/graphiql', 'code': 200, 'text': 'GraphiQL'},
    {'uri': '/_cluster/health', 'code': 200, 'text': 'cluster_name'},       # Elasticsearch
    {'uri': '/solr/', 'code': 200, 'text': 'Solr'},
    {'uri': '/vault/ui/', 'code': 200, 'text': 'Vault'},                    # HashiCorp Vault
    {'uri': '/rabbitmq', 'code': 200, 'text': 'RabbitMQ'},
    {'uri': '/flower/', 'code': 200, 'text': 'Flower'},                     # Celery Flower
    {'uri': '/pma/', 'code': 200, 'text': 'phpMyAdmin'},
    {'uri': '/dbadmin/', 'code': 200, 'text': None}
]

async def fetch(location, path, session, results_list):
    uri = location + path['uri']
    log.debug('scanning %s - expecting %s', uri, path['code'])
    try:
        async with session.get(uri, ssl=False) as response:
            text = await response.text()
            matched = False
            matched_text = None

            if response.status == path['code']:
                if path['text'] is None:
                    log.info(f'found {path["code"]} at {uri}')
                    matched = True
                elif path['text'] in text:
                    log.info(f'found {path["code"]} at {uri}')
                    matched = True
                    matched_text = path['text']
                else:
                    log.debug(f'found {path["code"]} at {uri} but no match for {path["text"]}')
            else:
                log.debug(f'found {response.status} at {uri}')

            # Store result for reporting
            if matched:
                result = {
                    'path': path['uri'],
                    'status_code': response.status,
                    'expected_code': path['code'],
                    'description': _get_path_description(path['uri']),
                    'matched_text': matched_text
                }
                results_list.append(result)

    except Exception as e:
        log.error('error fetching %s - %s', uri, e)
        logging.debug(e)


def _get_path_description(uri):
    """Get human-readable description for a path"""
    descriptions = {
        '/server-status': 'Apache Server Status',
        '/install/index.php': 'Installation Wizard',
        '/server-info': 'Apache Server Info',
        '/wp-login.php': 'WordPress Login',
        '/xmlrpc.php': 'XML-RPC Endpoint',
        '/phpinfo.php': 'PHP Info Page',
        '/cpanel': 'cPanel',
        '/phpmyadmin/': 'phpMyAdmin',
        '/phpsysinfo/': 'phpSysInfo',
        '/adminer/': 'Adminer Database',
        '/joomla': 'Joomla CMS',
        '/drupal': 'Drupal CMS',
        '/jenkins': 'Jenkins CI/CD',
        '/grafana': 'Grafana Dashboard',
        '/kibana': 'Kibana Dashboard',
        '/.well-known/security.txt': 'Security Contact Info',
        '/manager/html': 'Apache Tomcat Manager',
        '/robots.txt': 'Robots.txt',
        '/sitemap.xml': 'Sitemap XML',
        '/admin': 'Admin Panel',
        '/administrator': 'Administrator Panel',
        '/wp-admin': 'WordPress Admin',
        '/.git': 'Git Repository',
        '/.env': 'Environment Config',
        '/config.php': 'PHP Configuration',
        '/backup.sql': 'SQL Backup',
        '/backup.tar.gz': 'Archive Backup',
        '/phpinfo.php': 'PHP Info',
        '/swagger-ui.html': 'Swagger API Docs',
        '/.DS_Store': 'macOS Metadata',
        '/server-status?auto': 'Apache Status (machine-readable, leaks addresses)',
        '/nginx_status': 'nginx stub_status (leaks connections)',
        '/stub_status': 'nginx stub_status (leaks connections)',
        '/status?full': 'PHP-FPM Status',
        '/fpm-status': 'PHP-FPM Status',
        '/php-fpm-status': 'PHP-FPM Status',
        '/metrics': 'Prometheus Metrics (instance labels leak IP:port)',
        '/debug/vars': 'Go expvar (cmdline / memstats)',
        '/debug/pprof/': 'Go pprof profiler',
        '/_profiler/': 'Symfony Profiler (leaks SERVER_ADDR = origin IP)',
        '/app_dev.php': 'Symfony Dev Front Controller',
        '/actuator': 'Spring Boot Actuator',
        '/actuator/health': 'Spring Boot Actuator Health',
        '/actuator/env': 'Spring Actuator Env (leaks vars & hostnames)',
        '/actuator/configprops': 'Spring Actuator Config Properties',
        '/actuator/mappings': 'Spring Actuator Mappings',
        '/actuator/heapdump': 'Spring Actuator Heap Dump (credentials & addresses)',
        '/telescope/requests': 'Laravel Telescope',
        '/horizon/api/stats': 'Laravel Horizon',
        '/_ignition/health-check': 'Laravel Ignition',
        '/.git/HEAD': 'Git Repository (HEAD)',
        '/.git/logs/HEAD': 'Git Reflog (author names & e-mails)',
        '/.svn/entries': 'Subversion Metadata',
        '/.svn/wc.db': 'Subversion Working Copy DB',
        '/.hg/store': 'Mercurial Store',
        '/.bzr/branch/last-revision': 'Bazaar Branch',
        '/humans.txt': 'humans.txt (operator names)',
        '/appsettings.json': '.NET App Settings (connection strings)',
        '/web.config': 'IIS web.config',
        '/docker-compose.yml': 'Docker Compose (service topology)',
        '/docker-compose.yaml': 'Docker Compose (service topology)',
        '/appsettings.Production.json': '.NET App Settings (production)',
        '/.aws/credentials': 'AWS Credentials',
        '/.ssh/id_rsa': 'SSH Private Key',
        '/.kube/config': 'Kubernetes Config',
        '/wp-json/wp/v2/users': 'WordPress User Enumeration',
        '/?rest_route=/wp/v2/users': 'WordPress User Enumeration',
        '/graphiql': 'GraphiQL Console',
        '/_cluster/health': 'Elasticsearch Cluster Health',
        '/solr/': 'Apache Solr Admin',
        '/vault/ui/': 'HashiCorp Vault',
        '/rabbitmq': 'RabbitMQ Management',
        '/flower/': 'Celery Flower',
        '/pma/': 'phpMyAdmin',
    }
    return descriptions.get(uri, 'Discovered Path')

async def main(location, usetor=True, max_concurrent_requests=5):
    if location.endswith('/'):
        location = location[:-1]
    if usetor:
        reqproxies = getsocks(aio_fmt=True)
    else:
        reqproxies = None
    logging.debug('requesting: %s - usetor:%s', location, usetor)
    logging.debug('using proxies: %s', reqproxies)
    timeout = ClientTimeout(total=30)
    sem = asyncio.Semaphore(max_concurrent_requests)
    connector = ProxyConnector.from_url(reqproxies.get('https')) if reqproxies else None

    # List to collect discovered paths
    results = []

    async with ClientSession(headers={'User-Agent': useragentstr}, timeout=timeout, trust_env=True, connector=connector) as session:
        catch_all_detected = await is_catch_all(session, location)
        if catch_all_detected:
            log.warning("catch-all response-code behavior detected - path-based checks will be skipped")
            return results
        tasks = []
        for path in interesting_paths:
            async with sem:
                tasks.append(fetch(location, path, session, results))
        await asyncio.gather(*tasks)

    return results
