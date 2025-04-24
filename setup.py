from setuptools import setup, find_packages

setup(
    name="bebop",
    version="0.1.0",
    packages=find_packages(),
    package_data={
        'app': ['*.py'],
    },
    include_package_data=True,
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
    entry_points={
        'console_scripts': [
            'bebop=app.__main__:main',
        ],
    },
) 