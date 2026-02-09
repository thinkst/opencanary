import codecs
import os.path
from setuptools import setup, find_namespace_packages


def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), "r") as fp:
        return fp.read()


def get_version(rel_path):
    """
    Reading the package version dynamically.
    https://packaging.python.org/en/latest/guides/single-sourcing-package-version/
    """
    for line in read(rel_path).splitlines():
        if line.startswith("__version__"):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError("Unable to find version string.")


def get_long_description():
    """
    Safely read README.md for long_description.
    """
    here = os.path.abspath(os.path.dirname(__file__))
    readme_path = os.path.join(here, "README.md")
    if not os.path.isfile(readme_path):
        return "A low interaction honeypot intended to be run on internal networks."
    with open(readme_path, encoding="utf-8") as f:
        return f.read()


requirements = [
    "Twisted==24.11.0",
    "pyasn1==0.4.5",
    "cryptography==46.0.4",
    "simplejson==3.16.0",
    "requests==2.32.4",
    "zope.interface==7.2",
    "PyPDF2==1.27.9",
    "fpdf==1.7.2",
    "passlib==1.7.1",
    "Jinja2==3.1.6",
    "ntlmlib==0.72",
    "bcrypt==3.1.7",
    "setuptools==78.1.1",
    "urllib3==2.6.3",
    "hpfeeds==3.0.0",
    "pyOpenSSL==25.3.0",
    "service-identity==21.1.0",
]

setup(
    name="opencanary",
    version=get_version("opencanary/__init__.py"),
    url="http://www.thinkst.com/",
    project_urls={
        "Bug Tracker": "https://github.com/thinkst/opencanary/issues",
        "Documentation": "https://github.com/thinkst/opencanary#readme",
        "Source Code": "https://github.com/thinkst/opencanary",
    },
    author="Thinkst Applied Research",
    author_email="info@thinkst.com",
    description="OpenCanary daemon",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    install_requires=requirements,
    license="BSD",
    packages=find_namespace_packages(
        exclude=["docs", "docs*" "opencanary.test", "opencanary.test*"]
    ),
    include_package_data=True,
    scripts=["bin/opencanaryd", "bin/opencanary.tac"],
    platforms="any",
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
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: BSD License",
    ],
)
