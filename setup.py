from setuptools import setup, find_packages

import sys
import opencanary

requirements = [
    'Twisted==19.10.0',
    'pyasn1==0.4.5',
    'cryptography==3.0',
    'simplejson==3.16.0',
    'requests==2.21.0',
    'zope.interface==5.0.0',
    'PyPDF2==1.26.0',
    'fpdf==1.7.2',
    'passlib==1.7.1',
    'Jinja2==2.10.1',
    'ntlmlib==0.72',
    'bcrypt==3.1.7',
    'hpfeeds==3.0.0']

if sys.version_info.major < 3:
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
    include_package_data=True,
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
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: BSD License",
    ],
)
