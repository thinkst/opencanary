import sys
from setuptools import setup, find_packages

import opencanary

requirements = [
    'Twisted==18.9.0',
    'pyasn1==0.4.5',
    'cryptography==2.5.0',
    'simplejson==3.16.0',
    'requests==2.21.0',
    'zope.interface==4.6.0',
    'PyPDF2==1.26.0',
    'fpdf==1.7.2',
    'passlib==1.7.1',
    'Jinja2==2.10.0',
    'ntlmlib==0.72',
    'hpfeeds3==0.9.8']

# Python 2 requires wsgiref but with python 3 wsgiref is a standard library.
if sys.version_info[0] < 3:
    requirements.append('wsgiref==0.1.2')


setup(
    name='opencanary',
    version=opencanary.__version__,
    url='http://www.thinkst.com/',
    author='Thinkst Applied Research',
    author_email='info@thinkst.com',
    description='OpenCanary daemon',
    long_description='A low interaction honeypot intended to be run on internal networks.',
    install_requires=requirements,
    setup_requires=[
        'setuptools_git'
    ],
    license='BSD',
    packages=find_packages(exclude='test'),
    scripts=['bin/opencanaryd','bin/opencanary.tac'],
    platforms='any',
    include_package_data=True
)
