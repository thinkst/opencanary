from setuptools import setup, find_packages

import os
import opencanary

setup(
    name='opencanary',
    version=opencanary.__version__,
    url='http://www.thinkst.com/',
    author='Thinkst Applied Research',
    author_email='info@thinkst.com',
    description='OpenCanary daemon',
    long_description='A low interaction honeypot intended to be run on internal networks.',
    install_requires=[
        'Jinja2>=2.4',
        'Twisted==18.4.0',
        'pyasn1==0.4.5',
        'pycrypto==2.6.1',
        'simplejson==3.16.0',
        'wsgiref==0.1.2',
        'requests==2.7.0',
        'zope.interface==4.4.2',
        'PyPDF2==1.26.0',
        'fpdf==1.7.2',
        'passlib==1.7.1',
        'ntlmlib==0.71'
    ],
    setup_requires=[
        'setuptools_git'
    ],
    license='BSD',
    packages = find_packages(exclude='test'),
    scripts=['bin/opencanaryd','bin/opencanary.tac'],
    platforms='any',
    include_package_data=True
)
