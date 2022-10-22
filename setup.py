import codecs
import os.path
from setuptools import setup, find_namespace_packages
import sys


def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), 'r') as fp:
        return fp.read()

def get_version(rel_path):
    """
    Reading the package version dynamically.
    https://packaging.python.org/en/latest/guides/single-sourcing-package-version/
    """
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError("Unable to find version string.")

requirements = [
    'Twisted==22.8.0',
    'pyasn1==0.4.5',
    'cryptography==38.0.1',
    'simplejson==3.16.0',
    'requests==2.21.0',
    'zope.interface==5.0.0',
    'PyPDF2==1.26.0',
    'fpdf==1.7.2',
    'passlib==1.7.1',
    'Jinja2==3.0.1',
    'ntlmlib==0.72',
    'bcrypt==3.1.7',
    'setuptools==63.2.0',
    'hpfeeds==3.0.0',
    'pyOpenSSL==22.1.0',
    "service-identity==21.1.0"
]


setup(
    name='opencanary',
    version=get_version("opencanary/__init__.py"),
    url='http://www.thinkst.com/',
    author='Thinkst Applied Research',
    author_email='info@thinkst.com',
    description='OpenCanary daemon',
    long_description='A low interaction honeypot intended to be run on internal networks.',
    install_requires=requirements,
    license='BSD',
    packages=find_namespace_packages(
        exclude=[
            'docs','docs*'
            'opencanary.test','opencanary.test*'
        ]
    ),
    include_package_data = True,
    scripts=['bin/opencanaryd','bin/opencanary.tac'],
    platforms='any',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Framework :: Twisted",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Natural Language :: English",
        "Operating System :: Unix",
        "Operating System :: POSIX :: Linux",
        "Operating System :: POSIX :: BSD :: FreeBSD",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: BSD License",
    ],
)
