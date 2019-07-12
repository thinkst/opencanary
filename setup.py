from setuptools import setup, find_packages

import os
import sys
import opencanary

install_requirements = [
        'Jinja2>=2.4',
        'Twisted==18.4.0',
        'pyasn1==0.4.5',
        # 'pycrypto==2.6.1',
        'cryptography==2.6.1',
        'simplejson==3.16.0',
        'requests==2.7.0',
        'zope.interface==4.4.2',
        'PyPDF2==1.26.0',
        'fpdf==1.7.2',
        'passlib==1.7.1',
        'ntlmlib==0.71',
    ]

if sys.version_info.major < 3:
    install_requirements = install_requirements + ["wsgiref==0.1.2","hpfeeds==1.0"]
else:
    install_requirements.append("hpfeeds3")

setup(
    name='opencanary',
    version=opencanary.__version__,
    url='http://www.thinkst.com/',
    author='Thinkst Applied Research',
    author_email='info@thinkst.com',
    description='OpenCanary daemon',
    long_description='A low interaction honeypot intended to be run on internal networks.',
    install_requires=install_requirements,
    setup_requires=[
        'setuptools_git'
    ],
    license='BSD',
    packages = find_packages(exclude='test'),
    scripts=['bin/opencanaryd','bin/opencanary.tac'],
    platforms='any',
    include_package_data=True
)
