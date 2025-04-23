from setuptools import setup, find_packages

setup(
    name="bebop",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'requests',
        'beautifulsoup4',
        'mmh3',
        'cryptography',
        'idna',
        'tldextract',
        'censys',
        'shodan',
        'aiohttp',
        'aiohttp-socks',
        'pyOpenSSL',
    ],
    python_requires='>=3.6',
) 