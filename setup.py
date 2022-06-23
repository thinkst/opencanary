import codecs
import os.path
from setuptools import setup, find_packages
import sys

PY3 = sys.version_info > (3,)

# Only check unicode on Python 2, In Python 3 unicode is the default and we can just return the input.
if sys.version_info[0] < 3:
    jinja_version = '2.10.1'
else:
    jinja_version = '3.0.1'


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
    'Twisted==19.10.0',
    'pyasn1==0.4.5',
    'cryptography==3.0',
    'simplejson==3.16.0',
    'requests==2.21.0',
    'zope.interface==5.0.0',
    'PyPDF2==1.26.0',
    'fpdf==1.7.2',
    'passlib==1.7.1',
    'Jinja2=={}'.format(jinja_version),
    'ntlmlib==0.72',
    'bcrypt==3.1.7',
    'setuptools==44.0.0',
    'hpfeeds==3.0.0']

if sys.version_info.major < 3:
    requirements.append('wsgiref==0.1.2')

setup(
    name='opencanary',
    version=get_version("opencanary/__init__.py"),
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
