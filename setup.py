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
        'Twisted==14.0.2',
        'pyasn1==0.1.7',
        'pycrypto==2.6.1',
        'simplejson==3.6.5',
        'wsgiref==0.1.2',
        'zope.interface==4.1.1',
        'PyPDF2==1.23',
        'fpdf==1.7',
        'passlib==1.6.2',
        'Jinja2>=2.4',
        'ntlmlib==0.67'
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

