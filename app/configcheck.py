#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import uuid
import logging
import asyncio
import ipaddress
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

# Paths worth interrogating on a discovered service. Each entry:
#   uri  - request path
#   code - HTTP status that indicates a hit
#   text - substring that must appear in the body to confirm (None = any body
#          with the expected code counts; the catch-all guard above keeps this
#          from firing on sites that 200 everything)
#   desc - human-readable label shown in the report
#
# Ordering is by category. The categories most valuable for deanonymisation
# come first: anything that prints the origin's own address, internal
# hostnames, backend topology, or the operator's identity.
interesting_paths = [
    # ------------------------------------------------------------------ #
    # server status / info  - leak the origin's own & internal addresses  #
    # ------------------------------------------------------------------ #
    {'uri': '/server-status', 'code': 200, 'text': 'Apache', 'desc': 'Apache mod_status (client/server IPs)'},
    {'uri': '/server-status?auto', 'code': 200, 'text': 'Total Accesses', 'desc': 'Apache mod_status (machine-readable)'},
    {'uri': '/server-info', 'code': 200, 'text': 'Apache', 'desc': 'Apache mod_info (config & modules)'},
    {'uri': '/nginx_status', 'code': 200, 'text': 'Active connections', 'desc': 'nginx stub_status'},
    {'uri': '/nginx-status', 'code': 200, 'text': 'Active connections', 'desc': 'nginx stub_status'},
    {'uri': '/stub_status', 'code': 200, 'text': 'Active connections', 'desc': 'nginx stub_status'},
    {'uri': '/status?full', 'code': 200, 'text': 'accepted conn', 'desc': 'PHP-FPM status'},
    {'uri': '/fpm-status', 'code': 200, 'text': 'accepted conn', 'desc': 'PHP-FPM status'},
    {'uri': '/php-fpm-status', 'code': 200, 'text': 'accepted conn', 'desc': 'PHP-FPM status'},
    {'uri': '/php_fpm_status', 'code': 200, 'text': 'accepted conn', 'desc': 'PHP-FPM status'},
    {'uri': '/balancer-manager', 'code': 200, 'text': 'Balancer Manager', 'desc': 'Apache mod_proxy_balancer (backend IPs)'},
    {'uri': '/haproxy?stats', 'code': 200, 'text': 'HAProxy', 'desc': 'HAProxy stats (backend servers)'},
    {'uri': '/haproxy-status', 'code': 200, 'text': 'HAProxy', 'desc': 'HAProxy stats'},
    {'uri': '/apc.php', 'code': 200, 'text': 'APC', 'desc': 'APC opcache status'},
    {'uri': '/opcache.php', 'code': 200, 'text': 'opcache', 'desc': 'OPcache status'},
    {'uri': '/phpsysinfo/', 'code': 200, 'text': 'phpSysInfo', 'desc': 'phpSysInfo (host details)'},
    {'uri': '/server_stats', 'code': 200, 'text': None, 'desc': 'Server statistics'},
    {'uri': '/awstats/', 'code': 200, 'text': 'AWStats', 'desc': 'AWStats (visitor IPs)'},

    # ------------------------------------------------------------------ #
    # metrics / health / telemetry                                        #
    # ------------------------------------------------------------------ #
    {'uri': '/metrics', 'code': 200, 'text': '# TYPE', 'desc': 'Prometheus metrics (instance labels leak IP:port)'},
    {'uri': '/actuator/prometheus', 'code': 200, 'text': '# TYPE', 'desc': 'Spring Actuator Prometheus metrics'},
    {'uri': '/debug/vars', 'code': 200, 'text': 'cmdline', 'desc': 'Go expvar (cmdline / memstats)'},
    {'uri': '/debug/pprof/', 'code': 200, 'text': 'profiles', 'desc': 'Go pprof profiler'},
    {'uri': '/varz', 'code': 200, 'text': None, 'desc': 'varz telemetry'},
    {'uri': '/statusz', 'code': 200, 'text': None, 'desc': 'statusz telemetry'},
    {'uri': '/healthz', 'code': 200, 'text': None, 'desc': 'Kubernetes health probe'},
    {'uri': '/livez', 'code': 200, 'text': None, 'desc': 'liveness probe'},
    {'uri': '/readyz', 'code': 200, 'text': None, 'desc': 'readiness probe'},
    {'uri': '/health', 'code': 200, 'text': None, 'desc': 'Health endpoint'},
    {'uri': '/api/health', 'code': 200, 'text': None, 'desc': 'API health endpoint'},

    # ------------------------------------------------------------------ #
    # Spring Boot Actuator                                                 #
    # ------------------------------------------------------------------ #
    {'uri': '/actuator', 'code': 200, 'text': '_links', 'desc': 'Spring Boot Actuator index'},
    {'uri': '/actuator/health', 'code': 200, 'text': 'status', 'desc': 'Spring Actuator health'},
    {'uri': '/actuator/env', 'code': 200, 'text': 'propertySources', 'desc': 'Spring Actuator env (vars & hostnames)'},
    {'uri': '/actuator/configprops', 'code': 200, 'text': 'contexts', 'desc': 'Spring Actuator config properties'},
    {'uri': '/actuator/mappings', 'code': 200, 'text': 'dispatcherServlet', 'desc': 'Spring Actuator mappings'},
    {'uri': '/actuator/beans', 'code': 200, 'text': 'beans', 'desc': 'Spring Actuator beans'},
    {'uri': '/actuator/httptrace', 'code': 200, 'text': 'traces', 'desc': 'Spring Actuator HTTP trace (client IPs)'},
    {'uri': '/actuator/heapdump', 'code': 200, 'text': None, 'desc': 'Spring Actuator heap dump (secrets & addresses)'},
    {'uri': '/actuator/threaddump', 'code': 200, 'text': 'threads', 'desc': 'Spring Actuator thread dump'},
    {'uri': '/actuator/loggers', 'code': 200, 'text': 'levels', 'desc': 'Spring Actuator loggers'},
    {'uri': '/actuator/gateway/routes', 'code': 200, 'text': None, 'desc': 'Spring Cloud Gateway routes (backends)'},
    {'uri': '/env', 'code': 200, 'text': 'propertySources', 'desc': 'Spring Actuator env (legacy path)'},
    {'uri': '/jolokia', 'code': 200, 'text': 'agent', 'desc': 'Jolokia JMX bridge'},
    {'uri': '/jolokia/list', 'code': 200, 'text': None, 'desc': 'Jolokia JMX list'},

    # ------------------------------------------------------------------ #
    # framework debug consoles  (Symfony prints SERVER_ADDR = origin IP)  #
    # ------------------------------------------------------------------ #
    {'uri': '/_profiler/', 'code': 200, 'text': 'Profiler', 'desc': 'Symfony profiler (SERVER_ADDR = origin IP)'},
    {'uri': '/_profiler/latest', 'code': 200, 'text': 'Profiler', 'desc': 'Symfony profiler (latest)'},
    {'uri': '/app_dev.php', 'code': 200, 'text': None, 'desc': 'Symfony dev front controller'},
    {'uri': '/_wdt', 'code': 200, 'text': None, 'desc': 'Symfony web debug toolbar'},
    {'uri': '/telescope/requests', 'code': 200, 'text': 'Telescope', 'desc': 'Laravel Telescope'},
    {'uri': '/horizon', 'code': 200, 'text': 'Horizon', 'desc': 'Laravel Horizon'},
    {'uri': '/horizon/api/stats', 'code': 200, 'text': None, 'desc': 'Laravel Horizon stats'},
    {'uri': '/_ignition/health-check', 'code': 200, 'text': 'can_execute_commands', 'desc': 'Laravel Ignition'},
    {'uri': '/_debugbar/open', 'code': 200, 'text': None, 'desc': 'Laravel Debugbar'},
    {'uri': '/__clockwork', 'code': 200, 'text': None, 'desc': 'Clockwork profiler'},
    {'uri': '/__debug__/', 'code': 200, 'text': None, 'desc': 'Django debug toolbar'},
    {'uri': '/rails/info/properties', 'code': 200, 'text': 'Rails', 'desc': 'Rails info (version & env)'},
    {'uri': '/rails/info/routes', 'code': 200, 'text': None, 'desc': 'Rails routes'},
    {'uri': '/sidekiq', 'code': 200, 'text': 'Sidekiq', 'desc': 'Sidekiq dashboard'},
    {'uri': '/console', 'code': 200, 'text': 'Werkzeug', 'desc': 'Werkzeug/Flask debugger console'},
    {'uri': '/debug/default/view', 'code': 200, 'text': None, 'desc': 'Yii debug panel'},

    # ------------------------------------------------------------------ #
    # version control  (remote URLs, commit author names & e-mails)       #
    # ------------------------------------------------------------------ #
    {'uri': '/.git', 'code': 200, 'text': None, 'desc': 'Git repository directory'},
    {'uri': '/.git/HEAD', 'code': 200, 'text': 'ref:', 'desc': 'Git HEAD'},
    {'uri': '/.git/config', 'code': 200, 'text': None, 'desc': 'Git config (remote URLs)'},
    {'uri': '/.git/logs/HEAD', 'code': 200, 'text': None, 'desc': 'Git reflog (author names & e-mails)'},
    {'uri': '/.git/index', 'code': 200, 'text': None, 'desc': 'Git index'},
    {'uri': '/.git/packed-refs', 'code': 200, 'text': None, 'desc': 'Git packed refs'},
    {'uri': '/.gitignore', 'code': 200, 'text': None, 'desc': 'gitignore'},
    {'uri': '/.gitattributes', 'code': 200, 'text': None, 'desc': 'gitattributes'},
    {'uri': '/.svn/entries', 'code': 200, 'text': None, 'desc': 'Subversion entries'},
    {'uri': '/.svn/wc.db', 'code': 200, 'text': None, 'desc': 'Subversion working-copy DB'},
    {'uri': '/.hg/store', 'code': 200, 'text': None, 'desc': 'Mercurial store'},
    {'uri': '/.hg/requires', 'code': 200, 'text': None, 'desc': 'Mercurial requires'},
    {'uri': '/.bzr/branch/last-revision', 'code': 200, 'text': None, 'desc': 'Bazaar branch'},
    {'uri': '/CVS/Root', 'code': 200, 'text': None, 'desc': 'CVS root (server host)'},
    {'uri': '/CVS/Entries', 'code': 200, 'text': None, 'desc': 'CVS entries'},

    # ------------------------------------------------------------------ #
    # config & secret files                                               #
    # ------------------------------------------------------------------ #
    {'uri': '/.env', 'code': 200, 'text': None, 'desc': 'Environment file'},
    {'uri': '/.env.local', 'code': 200, 'text': None, 'desc': 'Environment file (local)'},
    {'uri': '/.env.production', 'code': 200, 'text': None, 'desc': 'Environment file (production)'},
    {'uri': '/.env.prod', 'code': 200, 'text': None, 'desc': 'Environment file (prod)'},
    {'uri': '/.env.dev', 'code': 200, 'text': None, 'desc': 'Environment file (dev)'},
    {'uri': '/.env.development', 'code': 200, 'text': None, 'desc': 'Environment file (development)'},
    {'uri': '/.env.staging', 'code': 200, 'text': None, 'desc': 'Environment file (staging)'},
    {'uri': '/.env.backup', 'code': 200, 'text': None, 'desc': 'Environment file (backup)'},
    {'uri': '/.env.bak', 'code': 200, 'text': None, 'desc': 'Environment file (bak)'},
    {'uri': '/.env.save', 'code': 200, 'text': None, 'desc': 'Environment file (save)'},
    {'uri': '/.env.old', 'code': 200, 'text': None, 'desc': 'Environment file (old)'},
    {'uri': '/.env.example', 'code': 200, 'text': None, 'desc': 'Environment file (example)'},
    {'uri': '/config.php', 'code': 200, 'text': None, 'desc': 'PHP configuration'},
    {'uri': '/config.php.bak', 'code': 200, 'text': None, 'desc': 'PHP configuration (backup)'},
    {'uri': '/config.inc.php', 'code': 200, 'text': None, 'desc': 'PHP configuration include'},
    {'uri': '/configuration.php', 'code': 200, 'text': None, 'desc': 'Joomla configuration'},
    {'uri': '/wp-config.php', 'code': 200, 'text': None, 'desc': 'WordPress config'},
    {'uri': '/wp-config.php.bak', 'code': 200, 'text': None, 'desc': 'WordPress config (backup)'},
    {'uri': '/wp-config.php.save', 'code': 200, 'text': None, 'desc': 'WordPress config (save)'},
    {'uri': '/wp-config.php.orig', 'code': 200, 'text': None, 'desc': 'WordPress config (orig)'},
    {'uri': '/wp-config.php~', 'code': 200, 'text': None, 'desc': 'WordPress config (~)'},
    {'uri': '/wp-config.php.old', 'code': 200, 'text': None, 'desc': 'WordPress config (old)'},
    {'uri': '/wp-config.php.txt', 'code': 200, 'text': None, 'desc': 'WordPress config (txt)'},
    {'uri': '/appsettings.json', 'code': 200, 'text': 'ConnectionStrings', 'desc': '.NET app settings (connection strings)'},
    {'uri': '/appsettings.Production.json', 'code': 200, 'text': None, 'desc': '.NET app settings (production)'},
    {'uri': '/appsettings.Development.json', 'code': 200, 'text': None, 'desc': '.NET app settings (development)'},
    {'uri': '/web.config', 'code': 200, 'text': 'configuration', 'desc': 'IIS web.config'},
    {'uri': '/web.config.bak', 'code': 200, 'text': None, 'desc': 'IIS web.config (backup)'},
    {'uri': '/application.properties', 'code': 200, 'text': None, 'desc': 'Spring properties'},
    {'uri': '/application.yml', 'code': 200, 'text': None, 'desc': 'Spring YAML config'},
    {'uri': '/config.yml', 'code': 200, 'text': None, 'desc': 'YAML config'},
    {'uri': '/config.yaml', 'code': 200, 'text': None, 'desc': 'YAML config'},
    {'uri': '/config.json', 'code': 200, 'text': None, 'desc': 'JSON config'},
    {'uri': '/config.xml', 'code': 200, 'text': None, 'desc': 'XML config'},
    {'uri': '/settings.py', 'code': 200, 'text': None, 'desc': 'Django settings'},
    {'uri': '/local_settings.py', 'code': 200, 'text': None, 'desc': 'Django local settings'},
    {'uri': '/secrets.json', 'code': 200, 'text': None, 'desc': 'Secrets (JSON)'},
    {'uri': '/secrets.yml', 'code': 200, 'text': None, 'desc': 'Secrets (YAML)'},
    {'uri': '/credentials.json', 'code': 200, 'text': None, 'desc': 'Credentials (JSON)'},
    {'uri': '/database.yml', 'code': 200, 'text': None, 'desc': 'Rails database config'},
    {'uri': '/config/database.yml', 'code': 200, 'text': None, 'desc': 'Rails database config'},
    {'uri': '/config/secrets.yml', 'code': 200, 'text': None, 'desc': 'Rails secrets'},
    {'uri': '/config/master.key', 'code': 200, 'text': None, 'desc': 'Rails master key'},
    {'uri': '/parameters.yml', 'code': 200, 'text': None, 'desc': 'Symfony parameters'},
    {'uri': '/.htpasswd', 'code': 200, 'text': None, 'desc': 'Apache htpasswd (hashes)'},
    {'uri': '/.htaccess', 'code': 200, 'text': None, 'desc': 'Apache htaccess'},
    {'uri': '/.my.cnf', 'code': 200, 'text': None, 'desc': 'MySQL client config (credentials)'},
    {'uri': '/my.cnf', 'code': 200, 'text': None, 'desc': 'MySQL config'},
    {'uri': '/php.ini', 'code': 200, 'text': None, 'desc': 'PHP ini'},
    {'uri': '/.user.ini', 'code': 200, 'text': None, 'desc': 'PHP per-directory ini'},
    {'uri': '/.pgpass', 'code': 200, 'text': None, 'desc': 'PostgreSQL password file'},
    {'uri': '/.netrc', 'code': 200, 'text': None, 'desc': 'netrc credentials'},
    {'uri': '/.npmrc', 'code': 200, 'text': None, 'desc': 'npm credentials'},
    {'uri': '/.pypirc', 'code': 200, 'text': None, 'desc': 'PyPI credentials'},
    {'uri': '/.dockercfg', 'code': 200, 'text': None, 'desc': 'Docker registry credentials'},
    {'uri': '/.docker/config.json', 'code': 200, 'text': None, 'desc': 'Docker config (registry auth)'},
    {'uri': '/.aws/credentials', 'code': 200, 'text': None, 'desc': 'AWS credentials'},
    {'uri': '/.aws/config', 'code': 200, 'text': None, 'desc': 'AWS config'},
    {'uri': '/.ssh/id_rsa', 'code': 200, 'text': None, 'desc': 'SSH private key (RSA)'},
    {'uri': '/.ssh/id_dsa', 'code': 200, 'text': None, 'desc': 'SSH private key (DSA)'},
    {'uri': '/.ssh/id_ecdsa', 'code': 200, 'text': None, 'desc': 'SSH private key (ECDSA)'},
    {'uri': '/.ssh/id_ed25519', 'code': 200, 'text': None, 'desc': 'SSH private key (ed25519)'},
    {'uri': '/.ssh/authorized_keys', 'code': 200, 'text': None, 'desc': 'SSH authorized_keys'},
    {'uri': '/.ssh/known_hosts', 'code': 200, 'text': None, 'desc': 'SSH known_hosts (peer hosts)'},
    {'uri': '/id_rsa', 'code': 200, 'text': None, 'desc': 'SSH private key'},
    {'uri': '/.kube/config', 'code': 200, 'text': None, 'desc': 'Kubernetes config (cluster endpoints)'},
    {'uri': '/terraform.tfstate', 'code': 200, 'text': None, 'desc': 'Terraform state (secrets & IPs)'},
    {'uri': '/terraform.tfstate.backup', 'code': 200, 'text': None, 'desc': 'Terraform state (backup)'},
    {'uri': '/.vault-token', 'code': 200, 'text': None, 'desc': 'Vault token'},

    # ------------------------------------------------------------------ #
    # cloud / container / CI-CD manifests                                 #
    # ------------------------------------------------------------------ #
    {'uri': '/docker-compose.yml', 'code': 200, 'text': 'services', 'desc': 'Docker Compose (service topology)'},
    {'uri': '/docker-compose.yaml', 'code': 200, 'text': 'services', 'desc': 'Docker Compose (service topology)'},
    {'uri': '/docker-compose.override.yml', 'code': 200, 'text': None, 'desc': 'Docker Compose override'},
    {'uri': '/docker-compose.prod.yml', 'code': 200, 'text': None, 'desc': 'Docker Compose (prod)'},
    {'uri': '/Dockerfile', 'code': 200, 'text': None, 'desc': 'Dockerfile'},
    {'uri': '/.dockerignore', 'code': 200, 'text': None, 'desc': 'dockerignore'},
    {'uri': '/.dockerenv', 'code': 200, 'text': None, 'desc': 'Docker environment marker'},
    {'uri': '/deployment.yaml', 'code': 200, 'text': None, 'desc': 'Kubernetes deployment'},
    {'uri': '/k8s.yml', 'code': 200, 'text': None, 'desc': 'Kubernetes manifest'},
    {'uri': '/helm/values.yaml', 'code': 200, 'text': None, 'desc': 'Helm values'},
    {'uri': '/ansible.cfg', 'code': 200, 'text': None, 'desc': 'Ansible config'},
    {'uri': '/playbook.yml', 'code': 200, 'text': None, 'desc': 'Ansible playbook'},
    {'uri': '/inventory', 'code': 200, 'text': None, 'desc': 'Ansible inventory (hosts)'},
    {'uri': '/Vagrantfile', 'code': 200, 'text': None, 'desc': 'Vagrantfile'},
    {'uri': '/serverless.yml', 'code': 200, 'text': None, 'desc': 'Serverless framework config'},
    {'uri': '/.circleci/config.yml', 'code': 200, 'text': None, 'desc': 'CircleCI config'},
    {'uri': '/.travis.yml', 'code': 200, 'text': None, 'desc': 'Travis CI config'},
    {'uri': '/.gitlab-ci.yml', 'code': 200, 'text': None, 'desc': 'GitLab CI config'},
    {'uri': '/bitbucket-pipelines.yml', 'code': 200, 'text': None, 'desc': 'Bitbucket Pipelines config'},
    {'uri': '/Jenkinsfile', 'code': 200, 'text': None, 'desc': 'Jenkinsfile'},
    {'uri': '/azure-pipelines.yml', 'code': 200, 'text': None, 'desc': 'Azure Pipelines config'},
    {'uri': '/cloudbuild.yaml', 'code': 200, 'text': None, 'desc': 'Google Cloud Build config'},
    {'uri': '/buildspec.yml', 'code': 200, 'text': None, 'desc': 'AWS CodeBuild spec'},
    {'uri': '/vercel.json', 'code': 200, 'text': None, 'desc': 'Vercel config'},
    {'uri': '/netlify.toml', 'code': 200, 'text': None, 'desc': 'Netlify config'},

    # ------------------------------------------------------------------ #
    # backups / archives / database dumps                                 #
    # ------------------------------------------------------------------ #
    {'uri': '/backup.sql', 'code': 200, 'text': None, 'desc': 'SQL backup'},
    {'uri': '/backup.zip', 'code': 200, 'text': None, 'desc': 'ZIP backup'},
    {'uri': '/backup.tar.gz', 'code': 200, 'text': None, 'desc': 'tar.gz backup'},
    {'uri': '/backup.tar', 'code': 200, 'text': None, 'desc': 'tar backup'},
    {'uri': '/backup.tgz', 'code': 200, 'text': None, 'desc': 'tgz backup'},
    {'uri': '/backup.rar', 'code': 200, 'text': None, 'desc': 'RAR backup'},
    {'uri': '/backup.7z', 'code': 200, 'text': None, 'desc': '7z backup'},
    {'uri': '/db.sql', 'code': 200, 'text': None, 'desc': 'Database dump'},
    {'uri': '/database.sql', 'code': 200, 'text': None, 'desc': 'Database dump'},
    {'uri': '/dump.sql', 'code': 200, 'text': None, 'desc': 'Database dump'},
    {'uri': '/data.sql', 'code': 200, 'text': None, 'desc': 'Database dump'},
    {'uri': '/export.sql', 'code': 200, 'text': None, 'desc': 'Database export'},
    {'uri': '/dump.rdb', 'code': 200, 'text': None, 'desc': 'Redis dump'},
    {'uri': '/www.zip', 'code': 200, 'text': None, 'desc': 'Web root archive'},
    {'uri': '/www.tar.gz', 'code': 200, 'text': None, 'desc': 'Web root archive'},
    {'uri': '/site.zip', 'code': 200, 'text': None, 'desc': 'Site archive'},
    {'uri': '/web.zip', 'code': 200, 'text': None, 'desc': 'Web archive'},
    {'uri': '/html.zip', 'code': 200, 'text': None, 'desc': 'HTML archive'},
    {'uri': '/public_html.zip', 'code': 200, 'text': None, 'desc': 'public_html archive'},
    {'uri': '/wwwroot.zip', 'code': 200, 'text': None, 'desc': 'wwwroot archive'},
    {'uri': '/release.zip', 'code': 200, 'text': None, 'desc': 'Release archive'},
    {'uri': '/source.zip', 'code': 200, 'text': None, 'desc': 'Source archive'},

    # ------------------------------------------------------------------ #
    # log files                                                           #
    # ------------------------------------------------------------------ #
    {'uri': '/error_log', 'code': 200, 'text': None, 'desc': 'Error log'},
    {'uri': '/error.log', 'code': 200, 'text': None, 'desc': 'Error log'},
    {'uri': '/access_log', 'code': 200, 'text': None, 'desc': 'Access log (client IPs)'},
    {'uri': '/access.log', 'code': 200, 'text': None, 'desc': 'Access log (client IPs)'},
    {'uri': '/debug.log', 'code': 200, 'text': None, 'desc': 'WordPress debug log'},
    {'uri': '/wp-content/debug.log', 'code': 200, 'text': None, 'desc': 'WordPress debug log'},
    {'uri': '/storage/logs/laravel.log', 'code': 200, 'text': None, 'desc': 'Laravel log'},
    {'uri': '/application.log', 'code': 200, 'text': None, 'desc': 'Application log'},
    {'uri': '/app.log', 'code': 200, 'text': None, 'desc': 'Application log'},
    {'uri': '/npm-debug.log', 'code': 200, 'text': None, 'desc': 'npm debug log'},

    # ------------------------------------------------------------------ #
    # admin panels & database tools                                       #
    # ------------------------------------------------------------------ #
    {'uri': '/phpmyadmin/', 'code': 200, 'text': 'phpMyAdmin', 'desc': 'phpMyAdmin'},
    {'uri': '/pma/', 'code': 200, 'text': 'phpMyAdmin', 'desc': 'phpMyAdmin'},
    {'uri': '/myadmin/', 'code': 200, 'text': 'phpMyAdmin', 'desc': 'phpMyAdmin'},
    {'uri': '/dbadmin/', 'code': 200, 'text': None, 'desc': 'Database admin'},
    {'uri': '/adminer.php', 'code': 200, 'text': 'Adminer', 'desc': 'Adminer'},
    {'uri': '/adminer/', 'code': 200, 'text': 'Adminer', 'desc': 'Adminer'},
    {'uri': '/mongo-express', 'code': 200, 'text': None, 'desc': 'mongo-express'},
    {'uri': '/pgadmin', 'code': 200, 'text': 'pgAdmin', 'desc': 'pgAdmin'},
    {'uri': '/pgadmin4', 'code': 200, 'text': 'pgAdmin', 'desc': 'pgAdmin'},
    {'uri': '/cpanel', 'code': 200, 'text': 'cPanel', 'desc': 'cPanel'},
    {'uri': '/whm', 'code': 200, 'text': 'WHM', 'desc': 'WebHost Manager'},
    {'uri': '/plesk', 'code': 200, 'text': 'Plesk', 'desc': 'Plesk'},
    {'uri': '/webmin', 'code': 200, 'text': 'Webmin', 'desc': 'Webmin'},
    {'uri': '/manager/html', 'code': 200, 'text': 'Apache Tomcat', 'desc': 'Apache Tomcat Manager'},
    {'uri': '/host-manager/html', 'code': 200, 'text': 'Tomcat', 'desc': 'Apache Tomcat Host Manager'},
    {'uri': '/manager/status', 'code': 200, 'text': 'Tomcat', 'desc': 'Apache Tomcat Manager Status'},
    {'uri': '/jmx-console', 'code': 200, 'text': 'JBoss', 'desc': 'JBoss JMX console'},
    {'uri': '/web-console', 'code': 200, 'text': 'JBoss', 'desc': 'JBoss web console'},
    {'uri': '/admin', 'code': 200, 'text': None, 'desc': 'Admin panel'},
    {'uri': '/administrator', 'code': 200, 'text': None, 'desc': 'Administrator panel (Joomla)'},
    {'uri': '/admin.php', 'code': 200, 'text': None, 'desc': 'Admin entry point'},
    {'uri': '/admin/login', 'code': 200, 'text': None, 'desc': 'Admin login'},
    {'uri': '/wp-admin', 'code': 200, 'text': None, 'desc': 'WordPress admin'},
    {'uri': '/wp-login.php', 'code': 200, 'text': 'login', 'desc': 'WordPress login'},
    {'uri': '/user/login', 'code': 200, 'text': None, 'desc': 'Drupal login'},
    {'uri': '/install/index.php', 'code': 200, 'text': 'Installation Wizard', 'desc': 'Installation wizard'},
    {'uri': '/install.php', 'code': 200, 'text': None, 'desc': 'Installer'},

    # ------------------------------------------------------------------ #
    # CMS-specific (versions, user enum, config)                          #
    # ------------------------------------------------------------------ #
    {'uri': '/wp-json/', 'code': 200, 'text': 'wp/v2', 'desc': 'WordPress REST API'},
    {'uri': '/wp-json/wp/v2/users', 'code': 200, 'text': 'slug', 'desc': 'WordPress user enumeration'},
    {'uri': '/?rest_route=/wp/v2/users', 'code': 200, 'text': 'slug', 'desc': 'WordPress user enumeration'},
    {'uri': '/wp-cron.php', 'code': 200, 'text': None, 'desc': 'WordPress cron'},
    {'uri': '/xmlrpc.php', 'code': 405, 'text': 'XML-RPC server accepts POST requests only', 'desc': 'WordPress XML-RPC'},
    # Enumerate XML-RPC methods (read-only). A pingback.ping in the list is the
    # classic WordPress out-of-band deanon vector - flag its availability.
    {'uri': '/xmlrpc.php', 'code': 200, 'text': 'pingback.ping', 'desc': 'WordPress XML-RPC methods (pingback SSRF vector)',
     'method': 'POST', 'headers': {'Content-Type': 'text/xml'},
     'data': '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'},
    {'uri': '/readme.html', 'code': 200, 'text': 'WordPress', 'desc': 'WordPress readme (version)'},
    {'uri': '/license.txt', 'code': 200, 'text': 'WordPress', 'desc': 'WordPress license (version)'},
    {'uri': '/joomla', 'code': 200, 'text': 'Joomla', 'desc': 'Joomla'},
    {'uri': '/sites/default/settings.php', 'code': 200, 'text': None, 'desc': 'Drupal settings'},
    {'uri': '/CHANGELOG.txt', 'code': 200, 'text': 'Drupal', 'desc': 'Drupal changelog (version)'},
    {'uri': '/core/CHANGELOG.txt', 'code': 200, 'text': 'Drupal', 'desc': 'Drupal 8+ changelog (version)'},
    {'uri': '/magento_version', 'code': 200, 'text': 'Magento', 'desc': 'Magento version'},
    {'uri': '/app/etc/local.xml', 'code': 200, 'text': None, 'desc': 'Magento config (credentials)'},
    {'uri': '/app/etc/env.php', 'code': 200, 'text': None, 'desc': 'Magento 2 env (credentials)'},
    {'uri': '/typo3/', 'code': 200, 'text': 'TYPO3', 'desc': 'TYPO3 backend'},
    {'uri': '/typo3conf/LocalConfiguration.php', 'code': 200, 'text': None, 'desc': 'TYPO3 config'},
    {'uri': '/ghost/', 'code': 200, 'text': 'Ghost', 'desc': 'Ghost admin'},
    {'uri': '/sitecore/', 'code': 200, 'text': 'Sitecore', 'desc': 'Sitecore'},
    {'uri': '/umbraco/', 'code': 200, 'text': 'Umbraco', 'desc': 'Umbraco'},
    {'uri': '/bitrix/', 'code': 200, 'text': 'Bitrix', 'desc': 'Bitrix'},
    {'uri': '/modx', 'code': 200, 'text': 'MODX', 'desc': 'MODX'},
    {'uri': '/symfony', 'code': 200, 'text': 'Symfony', 'desc': 'Symfony'},
    {'uri': '/redmine', 'code': 200, 'text': 'Redmine', 'desc': 'Redmine'},

    # ------------------------------------------------------------------ #
    # API docs / introspection                                            #
    # ------------------------------------------------------------------ #
    {'uri': '/swagger', 'code': 200, 'text': 'Swagger', 'desc': 'Swagger UI'},
    {'uri': '/swagger-ui.html', 'code': 200, 'text': 'Swagger', 'desc': 'Swagger UI'},
    {'uri': '/swagger-ui/', 'code': 200, 'text': 'Swagger', 'desc': 'Swagger UI'},
    {'uri': '/swagger/index.html', 'code': 200, 'text': 'Swagger', 'desc': 'Swagger UI'},
    {'uri': '/swagger.json', 'code': 200, 'text': 'swagger', 'desc': 'Swagger spec'},
    {'uri': '/openapi.json', 'code': 200, 'text': 'openapi', 'desc': 'OpenAPI spec'},
    {'uri': '/v2/api-docs', 'code': 200, 'text': None, 'desc': 'Springfox API docs'},
    {'uri': '/v3/api-docs', 'code': 200, 'text': 'openapi', 'desc': 'OpenAPI 3 API docs'},
    {'uri': '/api-docs', 'code': 200, 'text': None, 'desc': 'API docs'},
    {'uri': '/redoc', 'code': 200, 'text': 'ReDoc', 'desc': 'ReDoc API docs'},
    # POST an introspection query - a permissive endpoint returns its full
    # schema (internal types, fields, backend mutations).
    {'uri': '/graphql', 'code': 200, 'text': '__schema', 'desc': 'GraphQL introspection (schema disclosure)',
     'method': 'POST', 'json': {'query': '{__schema{queryType{name}}}'}},
    {'uri': '/api/graphql', 'code': 200, 'text': '__schema', 'desc': 'GraphQL introspection (schema disclosure)',
     'method': 'POST', 'json': {'query': '{__schema{queryType{name}}}'}},
    {'uri': '/v1/graphql', 'code': 200, 'text': '__schema', 'desc': 'Hasura GraphQL introspection',
     'method': 'POST', 'json': {'query': '{__schema{queryType{name}}}'}},
    {'uri': '/query', 'code': 200, 'text': '__schema', 'desc': 'GraphQL introspection (schema disclosure)',
     'method': 'POST', 'json': {'query': '{__schema{queryType{name}}}'}},
    {'uri': '/graphiql', 'code': 200, 'text': 'GraphiQL', 'desc': 'GraphiQL console'},
    {'uri': '/playground', 'code': 200, 'text': 'playground', 'desc': 'GraphQL Playground'},
    {'uri': '/?wsdl', 'code': 200, 'text': 'definitions', 'desc': 'SOAP WSDL'},

    # ------------------------------------------------------------------ #
    # search / data stores exposed over HTTP                              #
    # ------------------------------------------------------------------ #
    {'uri': '/_cat/indices', 'code': 200, 'text': None, 'desc': 'Elasticsearch indices'},
    {'uri': '/_cluster/health', 'code': 200, 'text': 'cluster_name', 'desc': 'Elasticsearch cluster health'},
    {'uri': '/_nodes', 'code': 200, 'text': None, 'desc': 'Elasticsearch nodes (internal IPs)'},
    {'uri': '/_search', 'code': 200, 'text': 'hits', 'desc': 'Elasticsearch search'},
    {'uri': '/_search', 'code': 200, 'text': 'hits', 'desc': 'Elasticsearch search (match_all)',
     'method': 'POST', 'json': {'query': {'match_all': {}}, 'size': 1}},
    {'uri': '/_sql', 'code': 200, 'text': 'columns', 'desc': 'Elasticsearch SQL',
     'method': 'POST', 'json': {'query': 'SHOW TABLES'}},
    {'uri': '/solr/', 'code': 200, 'text': 'Solr', 'desc': 'Apache Solr'},
    {'uri': '/solr/admin/cores', 'code': 200, 'text': None, 'desc': 'Apache Solr cores'},
    {'uri': '/kibana', 'code': 200, 'text': 'Kibana', 'desc': 'Kibana'},
    {'uri': '/app/kibana', 'code': 200, 'text': 'Kibana', 'desc': 'Kibana'},
    {'uri': '/_plugin/head/', 'code': 200, 'text': None, 'desc': 'Elasticsearch Head plugin'},
    {'uri': '/_utils/', 'code': 200, 'text': 'Futon', 'desc': 'CouchDB Futon'},

    # ------------------------------------------------------------------ #
    # monitoring / infra dashboards                                       #
    # ------------------------------------------------------------------ #
    {'uri': '/grafana', 'code': 200, 'text': 'Grafana', 'desc': 'Grafana'},
    {'uri': '/grafana/login', 'code': 200, 'text': 'Grafana', 'desc': 'Grafana login'},
    {'uri': '/prometheus', 'code': 200, 'text': None, 'desc': 'Prometheus'},
    {'uri': '/alertmanager', 'code': 200, 'text': None, 'desc': 'Alertmanager'},
    {'uri': '/consul', 'code': 200, 'text': 'Consul', 'desc': 'Consul'},
    {'uri': '/v1/agent/self', 'code': 200, 'text': 'Config', 'desc': 'Consul agent (node info & IPs)'},
    {'uri': '/nomad', 'code': 200, 'text': 'Nomad', 'desc': 'Nomad'},
    {'uri': '/vault', 'code': 200, 'text': 'Vault', 'desc': 'HashiCorp Vault'},
    {'uri': '/vault/ui/', 'code': 200, 'text': 'Vault', 'desc': 'HashiCorp Vault UI'},
    {'uri': '/v1/sys/health', 'code': 200, 'text': None, 'desc': 'Vault health'},
    {'uri': '/traefik', 'code': 200, 'text': 'Traefik', 'desc': 'Traefik dashboard'},
    {'uri': '/api/rawdata', 'code': 200, 'text': None, 'desc': 'Traefik API (backends)'},
    {'uri': '/rabbitmq', 'code': 200, 'text': 'RabbitMQ', 'desc': 'RabbitMQ management'},
    {'uri': '/api/overview', 'code': 200, 'text': 'rabbitmq_version', 'desc': 'RabbitMQ API overview'},
    {'uri': '/flower/', 'code': 200, 'text': 'Flower', 'desc': 'Celery Flower'},
    {'uri': '/portainer', 'code': 200, 'text': 'Portainer', 'desc': 'Portainer'},
    {'uri': '/jenkins', 'code': 200, 'text': 'Jenkins', 'desc': 'Jenkins'},
    {'uri': '/netdata', 'code': 200, 'text': 'netdata', 'desc': 'Netdata (host metrics)'},
    {'uri': '/zabbix', 'code': 200, 'text': 'Zabbix', 'desc': 'Zabbix'},
    {'uri': '/nagios', 'code': 200, 'text': 'Nagios', 'desc': 'Nagios'},
    {'uri': '/munin/', 'code': 200, 'text': 'Munin', 'desc': 'Munin'},
    {'uri': '/cacti', 'code': 200, 'text': 'Cacti', 'desc': 'Cacti'},
    {'uri': '/grafana/api/health', 'code': 200, 'text': 'version', 'desc': 'Grafana health (version)'},

    # ------------------------------------------------------------------ #
    # package-manager / build manifests (dependencies & internal paths)   #
    # ------------------------------------------------------------------ #
    {'uri': '/composer.json', 'code': 200, 'text': None, 'desc': 'Composer manifest'},
    {'uri': '/composer.lock', 'code': 200, 'text': None, 'desc': 'Composer lockfile'},
    {'uri': '/package.json', 'code': 200, 'text': None, 'desc': 'npm manifest'},
    {'uri': '/package-lock.json', 'code': 200, 'text': None, 'desc': 'npm lockfile'},
    {'uri': '/yarn.lock', 'code': 200, 'text': None, 'desc': 'Yarn lockfile'},
    {'uri': '/Gemfile', 'code': 200, 'text': None, 'desc': 'Ruby Gemfile'},
    {'uri': '/Gemfile.lock', 'code': 200, 'text': None, 'desc': 'Ruby Gemfile lock'},
    {'uri': '/requirements.txt', 'code': 200, 'text': None, 'desc': 'Python requirements'},
    {'uri': '/Pipfile', 'code': 200, 'text': None, 'desc': 'Pipfile'},
    {'uri': '/poetry.lock', 'code': 200, 'text': None, 'desc': 'Poetry lockfile'},
    {'uri': '/pyproject.toml', 'code': 200, 'text': None, 'desc': 'Python project config'},
    {'uri': '/go.mod', 'code': 200, 'text': None, 'desc': 'Go module'},
    {'uri': '/go.sum', 'code': 200, 'text': None, 'desc': 'Go checksums'},
    {'uri': '/Cargo.toml', 'code': 200, 'text': None, 'desc': 'Rust Cargo manifest'},
    {'uri': '/pom.xml', 'code': 200, 'text': None, 'desc': 'Maven POM'},
    {'uri': '/build.gradle', 'code': 200, 'text': None, 'desc': 'Gradle build'},
    {'uri': '/webpack.config.js', 'code': 200, 'text': None, 'desc': 'Webpack config'},
    {'uri': '/Makefile', 'code': 200, 'text': None, 'desc': 'Makefile'},
    {'uri': '/phpunit.xml', 'code': 200, 'text': None, 'desc': 'PHPUnit config'},
    {'uri': '/tsconfig.json', 'code': 200, 'text': None, 'desc': 'TypeScript config'},

    # ------------------------------------------------------------------ #
    # IDE / editor / OS leftovers                                         #
    # ------------------------------------------------------------------ #
    {'uri': '/.idea/workspace.xml', 'code': 200, 'text': None, 'desc': 'JetBrains workspace'},
    {'uri': '/.idea/', 'code': 200, 'text': None, 'desc': 'JetBrains project dir'},
    {'uri': '/.vscode/settings.json', 'code': 200, 'text': None, 'desc': 'VS Code settings'},
    {'uri': '/.vscode/', 'code': 200, 'text': None, 'desc': 'VS Code dir'},
    {'uri': '/.DS_Store', 'code': 200, 'text': None, 'desc': 'macOS directory metadata'},
    {'uri': '/Thumbs.db', 'code': 200, 'text': None, 'desc': 'Windows thumbnail cache'},
    {'uri': '/.project', 'code': 200, 'text': None, 'desc': 'Eclipse project'},
    {'uri': '/.settings/', 'code': 200, 'text': None, 'desc': 'Eclipse settings dir'},
    {'uri': '/nbproject/', 'code': 200, 'text': None, 'desc': 'NetBeans project dir'},
    {'uri': '/.editorconfig', 'code': 200, 'text': None, 'desc': 'EditorConfig'},

    # ------------------------------------------------------------------ #
    # info / attribution / discovery                                      #
    # ------------------------------------------------------------------ #
    {'uri': '/robots.txt', 'code': 200, 'text': None, 'desc': 'robots.txt (hidden paths)'},
    {'uri': '/sitemap.xml', 'code': 200, 'text': None, 'desc': 'Sitemap'},
    {'uri': '/humans.txt', 'code': 200, 'text': None, 'desc': 'humans.txt (operator names)'},
    {'uri': '/.well-known/security.txt', 'code': 200, 'text': 'Contact', 'desc': 'security.txt (contact)'},
    {'uri': '/security.txt', 'code': 200, 'text': 'Contact', 'desc': 'security.txt (contact)'},
    {'uri': '/.well-known/openid-configuration', 'code': 200, 'text': 'issuer', 'desc': 'OpenID configuration (issuer host)'},
    {'uri': '/crossdomain.xml', 'code': 200, 'text': 'cross-domain', 'desc': 'Flash cross-domain policy'},
    {'uri': '/README.md', 'code': 200, 'text': None, 'desc': 'README'},
    {'uri': '/CHANGELOG.md', 'code': 200, 'text': None, 'desc': 'Changelog'},
    {'uri': '/LICENSE.txt', 'code': 200, 'text': None, 'desc': 'License'},
    {'uri': '/VERSION', 'code': 200, 'text': None, 'desc': 'Version file'},
    {'uri': '/author.txt', 'code': 200, 'text': None, 'desc': 'Author file'},

    # ------------------------------------------------------------------ #
    # phpinfo & webshell / test artefacts                                 #
    # ------------------------------------------------------------------ #
    {'uri': '/phpinfo.php', 'code': 200, 'text': 'This program makes use of the Zend', 'desc': 'phpinfo() (SERVER_ADDR = origin IP)'},
    {'uri': '/info.php', 'code': 200, 'text': 'This program makes use of the Zend', 'desc': 'phpinfo() (SERVER_ADDR = origin IP)'},
    {'uri': '/i.php', 'code': 200, 'text': 'This program makes use of the Zend', 'desc': 'phpinfo()'},
    {'uri': '/test.php', 'code': 200, 'text': None, 'desc': 'Test script'},
    {'uri': '/debug.php', 'code': 200, 'text': None, 'desc': 'Debug script'},
    {'uri': '/shell.php', 'code': 200, 'text': None, 'desc': 'Possible webshell'},
    {'uri': '/upload.php', 'code': 200, 'text': None, 'desc': 'Upload handler'},

    # ------------------------------------------------------------------ #
    # exposed directories                                                 #
    # ------------------------------------------------------------------ #
    {'uri': '/.env.dist', 'code': 200, 'text': None, 'desc': 'Environment template'},
    {'uri': '/backup/', 'code': 200, 'text': None, 'desc': 'Backup directory'},
    {'uri': '/backups/', 'code': 200, 'text': None, 'desc': 'Backup directory'},
    {'uri': '/uploads/', 'code': 200, 'text': None, 'desc': 'Uploads directory'},
    {'uri': '/files/', 'code': 200, 'text': None, 'desc': 'Files directory'},
    {'uri': '/logs/', 'code': 200, 'text': None, 'desc': 'Logs directory'},
    {'uri': '/tmp/', 'code': 200, 'text': None, 'desc': 'Temp directory'},
    {'uri': '/cache/', 'code': 200, 'text': None, 'desc': 'Cache directory'},
    {'uri': '/private/', 'code': 200, 'text': None, 'desc': 'Private directory'},
    {'uri': '/old/', 'code': 200, 'text': None, 'desc': 'Old directory'},
    {'uri': '/dev/', 'code': 200, 'text': None, 'desc': 'Dev directory'},
    {'uri': '/staging/', 'code': 200, 'text': None, 'desc': 'Staging directory'},
    {'uri': '/beta/', 'code': 200, 'text': None, 'desc': 'Beta directory'},
    {'uri': '/demo/', 'code': 200, 'text': None, 'desc': 'Demo directory'},
    {'uri': '/.well-known/', 'code': 200, 'text': None, 'desc': 'well-known directory'},

    # ------------------------------------------------------------------ #
    # orchestration / daemon APIs exposed over HTTP (leak topology & IPs) #
    # ------------------------------------------------------------------ #
    {'uri': '/info', 'code': 200, 'text': 'Containers', 'desc': 'Docker Engine API (info)'},
    {'uri': '/containers/json', 'code': 200, 'text': None, 'desc': 'Docker Engine API (running containers)'},
    {'uri': '/images/json', 'code': 200, 'text': None, 'desc': 'Docker Engine API (images)'},
    {'uri': '/api', 'code': 200, 'text': 'versions', 'desc': 'Kubernetes API server'},
    {'uri': '/apis', 'code': 200, 'text': 'groups', 'desc': 'Kubernetes API groups'},
    {'uri': '/v1/catalog/nodes', 'code': 200, 'text': 'Address', 'desc': 'Consul nodes (internal IPs)'},
    {'uri': '/v1/catalog/services', 'code': 200, 'text': None, 'desc': 'Consul services'},
    {'uri': '/v1/kv/?recurse=true', 'code': 200, 'text': None, 'desc': 'Consul KV (secrets)'},
    {'uri': '/v2/keys/?recursive=true', 'code': 200, 'text': 'nodes', 'desc': 'etcd keys (v2)'},

    # more Spring Actuator surface
    {'uri': '/actuator/metrics', 'code': 200, 'text': 'names', 'desc': 'Spring Actuator metrics'},
    {'uri': '/actuator/scheduledtasks', 'code': 200, 'text': None, 'desc': 'Spring Actuator scheduled tasks'},
    {'uri': '/actuator/caches', 'code': 200, 'text': None, 'desc': 'Spring Actuator caches'},
    {'uri': '/actuator/sessions', 'code': 200, 'text': None, 'desc': 'Spring Actuator sessions'},

    # more Go pprof - cmdline leaks flags (often incl. bind/advertise addresses)
    {'uri': '/debug/pprof/cmdline', 'code': 200, 'text': None, 'desc': 'Go pprof cmdline (flags & bind addrs)'},
    {'uri': '/debug/pprof/goroutine?debug=1', 'code': 200, 'text': 'goroutine', 'desc': 'Go pprof goroutine stacks'},

    # CI/build & script consoles
    {'uri': '/api/json', 'code': 200, 'text': 'jobs', 'desc': 'Jenkins API (jobs)'},
    {'uri': '/script', 'code': 200, 'text': 'Groovy', 'desc': 'Jenkins script console'},

    # ------------------------------------------------------------------ #
    # more POST vectors (introspection / RPC / analysis)                  #
    # ------------------------------------------------------------------ #
    {'uri': '/gql', 'code': 200, 'text': '__schema', 'desc': 'GraphQL introspection (schema disclosure)',
     'method': 'POST', 'json': {'query': '{__schema{queryType{name}}}'}},
    {'uri': '/api/v1/graphql', 'code': 200, 'text': '__schema', 'desc': 'GraphQL introspection (schema disclosure)',
     'method': 'POST', 'json': {'query': '{__schema{queryType{name}}}'}},
    {'uri': '/rpc', 'code': 200, 'text': 'jsonrpc', 'desc': 'JSON-RPC endpoint',
     'method': 'POST', 'json': {'jsonrpc': '2.0', 'method': 'web3_clientVersion', 'id': 1}},
    {'uri': '/', 'code': 200, 'text': 'jsonrpc', 'desc': 'JSON-RPC node at web root (client version)',
     'method': 'POST', 'json': {'jsonrpc': '2.0', 'method': 'web3_clientVersion', 'id': 1}},
    {'uri': '/_analyze', 'code': 200, 'text': 'tokens', 'desc': 'Elasticsearch analyze',
     'method': 'POST', 'json': {'text': 'bebop'}},

    # ------------------------------------------------------------------ #
    # shell / tool history & client configs (creds, internal hostnames)   #
    # ------------------------------------------------------------------ #
    {'uri': '/.bash_history', 'code': 200, 'text': None, 'desc': 'Bash history (commands, creds)'},
    {'uri': '/.zsh_history', 'code': 200, 'text': None, 'desc': 'Zsh history'},
    {'uri': '/.python_history', 'code': 200, 'text': None, 'desc': 'Python REPL history'},
    {'uri': '/.mysql_history', 'code': 200, 'text': None, 'desc': 'MySQL client history'},
    {'uri': '/.psql_history', 'code': 200, 'text': None, 'desc': 'psql history'},
    {'uri': '/.rediscli_history', 'code': 200, 'text': None, 'desc': 'redis-cli history'},
    {'uri': '/.viminfo', 'code': 200, 'text': None, 'desc': 'vim info (recent files/paths)'},
    {'uri': '/.ssh/config', 'code': 200, 'text': None, 'desc': 'SSH client config (internal hosts)'},
    {'uri': '/.s3cfg', 'code': 200, 'text': None, 'desc': 's3cmd config (AWS keys)'},
    {'uri': '/.boto', 'code': 200, 'text': None, 'desc': 'boto config (cloud keys)'},

    # ------------------------------------------------------------------ #
    # deploy/editor configs & keys (host + credentials, attribution)      #
    # ------------------------------------------------------------------ #
    {'uri': '/.gitconfig', 'code': 200, 'text': None, 'desc': 'Global git config (user name/e-mail)'},
    {'uri': '/.git-credentials', 'code': 200, 'text': None, 'desc': 'Git credentials (plaintext)'},
    {'uri': '/sftp-config.json', 'code': 200, 'text': None, 'desc': 'Sublime SFTP config (host & creds)'},
    {'uri': '/.vscode/sftp.json', 'code': 200, 'text': None, 'desc': 'VS Code SFTP config (host & creds)'},
    {'uri': '/deployment-config.json', 'code': 200, 'text': None, 'desc': 'Editor deploy config (host & creds)'},
    {'uri': '/.ftpconfig', 'code': 200, 'text': None, 'desc': 'FTP config (host & creds)'},
    {'uri': '/WS_FTP.LOG', 'code': 200, 'text': None, 'desc': 'WS_FTP log (upload hosts & paths)'},
    {'uri': '/storage/oauth-private.key', 'code': 200, 'text': None, 'desc': 'Laravel Passport private key'},
    {'uri': '/oauth-private.key', 'code': 200, 'text': None, 'desc': 'OAuth private key'},
    {'uri': '/privkey.pem', 'code': 200, 'text': None, 'desc': 'TLS private key'},
    {'uri': '/server.key', 'code': 200, 'text': None, 'desc': 'TLS private key'},
    {'uri': '/service-account.json', 'code': 200, 'text': None, 'desc': 'GCP service account key'},
    {'uri': '/.firebaserc', 'code': 200, 'text': None, 'desc': 'Firebase project config'},
    {'uri': '/CODEOWNERS', 'code': 200, 'text': None, 'desc': 'CODEOWNERS (maintainer handles)'},
    {'uri': '/.github/CODEOWNERS', 'code': 200, 'text': None, 'desc': 'CODEOWNERS (maintainer handles)'},

    # ------------------------------------------------------------------ #
    # more discovery / OAuth well-knowns                                  #
    # ------------------------------------------------------------------ #
    {'uri': '/.well-known/oauth-authorization-server', 'code': 200, 'text': 'issuer', 'desc': 'OAuth AS metadata (issuer host)'},
    {'uri': '/sitemap_index.xml', 'code': 200, 'text': None, 'desc': 'Sitemap index'},
    {'uri': '/wp-links-opml.php', 'code': 200, 'text': 'opml', 'desc': 'WordPress OPML (blogroll)'},

    # ------------------------------------------------------------------ #
    # cluster / monitoring endpoints that enumerate internal IPs (deanon) #
    # ------------------------------------------------------------------ #
    {'uri': '/api/v1/targets', 'code': 200, 'text': 'scrapeUrl', 'desc': 'Prometheus targets (internal scrape IPs)'},
    {'uri': '/api/v1/status/config', 'code': 200, 'text': 'yaml', 'desc': 'Prometheus config (scrape targets)'},
    {'uri': '/prometheus/api/v1/targets', 'code': 200, 'text': 'scrapeUrl', 'desc': 'Prometheus targets (proxied)'},
    {'uri': '/_membership', 'code': 200, 'text': 'cluster_nodes', 'desc': 'CouchDB cluster membership (node IPs)'},
    {'uri': '/_all_dbs', 'code': 200, 'text': None, 'desc': 'CouchDB database list'},
    {'uri': '/_node/_local/_config', 'code': 200, 'text': None, 'desc': 'CouchDB node config'},
    {'uri': '/query?q=SHOW+DATABASES', 'code': 200, 'text': 'results', 'desc': 'InfluxDB query (databases)'},
    {'uri': '/replicas_status', 'code': 200, 'text': None, 'desc': 'ClickHouse replica status'},
    {'uri': '/glances/api/3/all', 'code': 200, 'text': None, 'desc': 'Glances host stats (IPs)'},
    {'uri': '/glances/api/4/all', 'code': 200, 'text': None, 'desc': 'Glances host stats (IPs)'},
    {'uri': '/minio/health/live', 'code': 200, 'text': None, 'desc': 'MinIO health'},
    {'uri': '/debug/pprof/heap', 'code': 200, 'text': None, 'desc': 'Go pprof heap'},

    # ------------------------------------------------------------------ #
    # build / version / attribution (git commit, maintainers)            #
    # ------------------------------------------------------------------ #
    {'uri': '/actuator/info', 'code': 200, 'text': None, 'desc': 'Spring Actuator info (git commit/build)'},
    {'uri': '/META-INF/MANIFEST.MF', 'code': 200, 'text': None, 'desc': 'Java manifest (build/version)'},
    {'uri': '/version.json', 'code': 200, 'text': None, 'desc': 'Version manifest'},
    {'uri': '/build.json', 'code': 200, 'text': None, 'desc': 'Build manifest'},
    {'uri': '/REVISION', 'code': 200, 'text': None, 'desc': 'Deployed revision'},

    # ------------------------------------------------------------------ #
    # JS source maps (leak source tree paths, dev comments, usernames)    #
    # ------------------------------------------------------------------ #
    {'uri': '/main.js.map', 'code': 200, 'text': None, 'desc': 'JS source map (source paths)'},
    {'uri': '/app.js.map', 'code': 200, 'text': None, 'desc': 'JS source map'},
    {'uri': '/bundle.js.map', 'code': 200, 'text': None, 'desc': 'JS source map'},
    {'uri': '/static/js/main.js.map', 'code': 200, 'text': None, 'desc': 'JS source map (CRA)'},

    # ------------------------------------------------------------------ #
    # more framework configs / deploy secrets                            #
    # ------------------------------------------------------------------ #
    {'uri': '/config/credentials.yml.enc', 'code': 200, 'text': None, 'desc': 'Rails encrypted credentials'},
    {'uri': '/config/credentials/production.key', 'code': 200, 'text': None, 'desc': 'Rails production key'},
    {'uri': '/config/environments/production.rb', 'code': 200, 'text': None, 'desc': 'Rails production env'},
    {'uri': '/WEB-INF/classes/application.properties', 'code': 200, 'text': None, 'desc': 'Spring properties (WEB-INF)'},
    {'uri': '/WEB-INF/applicationContext.xml', 'code': 200, 'text': None, 'desc': 'Spring context (WEB-INF)'},
    {'uri': '/bootstrap.yml', 'code': 200, 'text': None, 'desc': 'Spring Cloud bootstrap config'},
    {'uri': '/nuxt.config.js', 'code': 200, 'text': None, 'desc': 'Nuxt config'},
    {'uri': '/next.config.js', 'code': 200, 'text': None, 'desc': 'Next.js config'},
    {'uri': '/ecosystem.config.js', 'code': 200, 'text': None, 'desc': 'PM2 ecosystem config (env)'},
    {'uri': '/uwsgi.ini', 'code': 200, 'text': None, 'desc': 'uWSGI config'},
    {'uri': '/manage.py', 'code': 200, 'text': None, 'desc': 'Django manage.py'},
    {'uri': '/wsgi.py', 'code': 200, 'text': None, 'desc': 'WSGI entry (paths)'},
    {'uri': '/.terraformrc', 'code': 200, 'text': None, 'desc': 'Terraform CLI config (creds)'},
    {'uri': '/terraform.tfvars', 'code': 200, 'text': None, 'desc': 'Terraform variables (secrets)'},
    {'uri': '/knife.rb', 'code': 200, 'text': None, 'desc': 'Chef knife config'},
    {'uri': '/user-data', 'code': 200, 'text': None, 'desc': 'cloud-init user-data (secrets)'},

    # ------------------------------------------------------------------ #
    # webmail / groupware & queue dashboards                             #
    # ------------------------------------------------------------------ #
    {'uri': '/rainloop/data/', 'code': 200, 'text': None, 'desc': 'RainLoop data dir (configs/creds)'},
    {'uri': '/roundcube/', 'code': 200, 'text': 'Roundcube', 'desc': 'Roundcube webmail'},
    {'uri': '/SOGo/', 'code': 200, 'text': 'SOGo', 'desc': 'SOGo groupware'},
    {'uri': '/admin/queues', 'code': 200, 'text': 'Bull', 'desc': 'Bull/BullMQ queue dashboard'},
    {'uri': '/resque', 'code': 200, 'text': 'Resque', 'desc': 'Resque dashboard'},

    # ------------------------------------------------------------------ #
    # more POST vectors (RPC / GraphQL mounts)                            #
    # ------------------------------------------------------------------ #
    {'uri': '/api_jsonrpc.php', 'code': 200, 'text': 'jsonrpc', 'desc': 'Zabbix API (apiinfo.version)',
     'method': 'POST', 'json': {'jsonrpc': '2.0', 'method': 'apiinfo.version', 'params': {}, 'id': 1}},
    {'uri': '/jsonrpc', 'code': 200, 'text': 'jsonrpc', 'desc': 'JSON-RPC endpoint',
     'method': 'POST', 'json': {'jsonrpc': '2.0', 'method': 'system.listMethods', 'id': 1}},
    {'uri': '/v2/graphql', 'code': 200, 'text': '__schema', 'desc': 'GraphQL introspection (schema disclosure)',
     'method': 'POST', 'json': {'query': '{__schema{queryType{name}}}'}},
    {'uri': '/admin/api', 'code': 200, 'text': '__schema', 'desc': 'GraphQL introspection (admin mount)',
     'method': 'POST', 'json': {'query': '{__schema{queryType{name}}}'}},
]

# --- origin-indicator extraction --------------------------------------- #
# A matched leak often prints the origin's real addressing in its body. We mine
# it here so the caller can feed it straight into the correlation/confirmation
# pipeline (a leaked SERVER_ADDR / instance= label is a candidate origin IP).

_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_IPV6_RE = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){3,7}[A-Fa-f0-9]{1,4}\b')
# hosts embedded in URLs / connection strings (jdbc:, redis://, mongodb://, ...)
_HOST_IN_URL_RE = re.compile(
    r'(?i)\b(?:https?|ftp|jdbc:[a-z0-9]+|redis|rediss|mongodb(?:\+srv)?|amqps?|'
    r'postgres(?:ql)?|mysql|mssql|memcached)://(?:[^:@/\s"\'<>]+(?::[^@/\s"\'<>]*)?@)?'
    r'([A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)')
# HOST-ish assignments in env / phpinfo / config bodies
_ASSIGN_HOST_RE = re.compile(
    r'(?i)(?:DB_HOST|DATABASE_HOST|REDIS_HOST|MAIL_HOST|SMTP_HOST|MYSQL_HOST|'
    r'PG_?HOST|SERVER_ADDR|SERVER_NAME|HOSTNAME|X-Forwarded-For|X-Real-IP)'
    r'["\']?\s*(?:=>|[:=])\s*["\']?\s*([A-Za-z0-9._:-]+)')
# Prometheus/Consul style: instance="1.2.3.4:9100"  "Address":"10.0.0.5"
_LABELLED_ADDR_RE = re.compile(
    r'(?i)(?:instance|address|advertise_addr|advertiseaddr|node_?ip|bind_?addr)'
    r'["\']?\s*[:=]\s*["\']?([0-9A-Fa-f.:]+)')

# third-party hosts that are never the origin - don't treat as candidates
_HOST_NOISE = (
    'w3.org', 'schema.org', 'googleapis.com', 'gstatic.com', 'google.com',
    'jquery.com', 'jsdelivr.net', 'cloudflare.com', 'bootstrapcdn.com',
    'fontawesome.com', 'gravatar.com', 'wordpress.org', 'example.com',
    'example.org', 'localhost', 'githubusercontent.com', 'github.com',
    'unpkg.com', 'polyfill.io', 'sentry.io', 'gmpg.org', 'purl.org',
)


def _keep_ip(token):
    '''Return ('public'|'private'|None) for a parsed IP token.'''
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        return None
    if ip.is_global:
        return 'public'
    if ip.is_private:
        return 'private'
    return None


def _clean_host(h):
    h = (h or '').strip().strip('.').lower()
    # drop a trailing :port if present
    if h.count(':') == 1 and not h.replace(':', '').isalpha():
        h = h.split(':', 1)[0]
    if not h or '.' not in h or h.endswith('.onion'):
        return None
    try:                                   # pure IPs handled elsewhere
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    if not re.match(r'^[a-z0-9.-]+$', h) or h.startswith('-'):
        return None
    if any(h == n or h.endswith('.' + n) for n in _HOST_NOISE):
        return None
    # require a plausible TLD (2+ alpha) to cut file names like config.php
    if not re.search(r'\.[a-z]{2,}$', h):
        return None
    return h


def extract_origin_indicators(text, limit=200000):
    '''Mine a matched response body for the origin's real addressing.'''
    out = {'public_ips': [], 'private_ips': [], 'hostnames': []}
    if not text:
        return out
    sample = text[:limit]
    pub, priv, hosts = set(), set(), set()
    for token in _IPV4_RE.findall(sample) + _IPV6_RE.findall(sample):
        kind = _keep_ip(token)
        if kind == 'public':
            pub.add(token)
        elif kind == 'private':
            priv.add(token)
    for rx in (_LABELLED_ADDR_RE,):
        for token in rx.findall(sample):
            kind = _keep_ip(token.split(':')[0] if token.count(':') == 1 else token)
            if kind == 'public':
                pub.add(token.split(':')[0] if token.count(':') == 1 else token)
    for rx in (_HOST_IN_URL_RE, _ASSIGN_HOST_RE):
        for token in rx.findall(sample):
            h = _clean_host(token)
            if h:
                hosts.add(h)
    out['public_ips'] = sorted(pub)[:20]
    out['private_ips'] = sorted(priv)[:20]
    out['hostnames'] = sorted(hosts)[:20]
    return out


async def fetch(location, path, session, results_list):
    uri = location + path['uri']
    method = path.get('method', 'GET')
    log.debug('scanning %s (%s) - expecting %s', uri, method, path['code'])
    try:
        async with session.request(method, uri, ssl=False,
                                   json=path.get('json'), data=path.get('data'),
                                   headers=path.get('headers')) as response:
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
                indicators = extract_origin_indicators(text)
                if indicators['public_ips'] or indicators['hostnames']:
                    log.warning('config leak at %s exposes origin indicators: %s',
                                path['uri'],
                                indicators['public_ips'] + indicators['hostnames'])
                result = {
                    'path': path['uri'],
                    'method': method,
                    'status_code': response.status,
                    'expected_code': path['code'],
                    'description': path.get('desc', 'Discovered Path'),
                    'matched_text': matched_text,
                    'indicators': indicators,
                }
                results_list.append(result)

    except Exception as e:
        log.error('error fetching %s - %s', uri, e)
        logging.debug(e)


async def _bounded_fetch(sem, location, path, session, results_list):
    # Actually bound concurrency: hold the semaphore for the duration of the
    # request. (The previous code guarded only coroutine *creation*, so every
    # path fired at once - fine for a short list, but this list routes hundreds
    # of requests through a single Tor circuit.)
    async with sem:
        await fetch(location, path, session, results_list)


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
        tasks = [
            _bounded_fetch(sem, location, path, session, results)
            for path in interesting_paths
        ]
        await asyncio.gather(*tasks)

    return results
