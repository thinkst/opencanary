# OpenCanary by Thinkst Canary

<img src="docs/logo.png" width="50" style="float: left"> OpenCanary is a multi-protocol network honeypot. It's primary use-case is to catch hackers after they've breached non-public networks. It has extremely low resource requirements and can be tweaked, modified, and extended.

[![OpenCanary Tests](https://github.com/thinkst/opencanary/actions/workflows/opencanary_tests.yml/badge.svg)](https://github.com/thinkst/opencanary/actions/workflows/opencanary_tests.yml)
[![Docker build](https://github.com/thinkst/opencanary/actions/workflows/docker-build.yml/badge.svg)](https://github.com/thinkst/opencanary/actions/workflows/docker-build.yml)
[![Publish to PyPI](https://github.com/thinkst/opencanary/actions/workflows/publish.yml/badge.svg)](https://github.com/thinkst/opencanary/actions/workflows/publish.yml)

## Overview

OpenCanary runs as a daemon and implements multiple common network protocols. When attackers breach networks and interact with the honeypot, OpenCanary will send you alerts via a variety of mechanisms.

OpenCanary is implemented in Python and so the core honeypot is cross-platform, however certain features require specific OSes. Running on Linux will give you the most options. It has extremely low resource requirements; for example it can be deployed happily on a Raspberry Pi, or a VM with minimal resources.

This README describes how to install and configure OpenCanary on Ubuntu Linux and MacOS.

OpenCanary is the Open Source version of our commercial [Thinkst Canary](https://canary.tools) honeypot.

## Table of Contents
- **[Prerequisites](#prerequisites)**
- **[Features](#features)**
- **[Installation](#installation)**
  - [Installation on Ubuntu](#installation-on-ubuntu)
  - [Installation on macOS](#installation-on-macos)
  - [Installation via Git](#installation-via-git)
  - [Installation for Docker](#installation-for-docker)
- **[Configuring OpenCanary](#configuring-opencanary)**
  - [Creating the initial configuration](#creating-the-initial-configuration)
  - [Enabling protocol modules and alerting](#enabling-protocol-modules-and-alerting)
  - [Optional modules](#optional-modules)
     - [SNMP](#snmp)
     - [Portscan](#portscan)
     - [Samba Setup](#samba-setup)
- **[Running OpenCanary](#running-opencanary)**
  - [Directly on Linux or macOS](#directly-on-linux-or-macos)
  - [With docker-compose](#with-docker-compose)
  - [With Docker](#with-docker)
- **[Documentation](#documentation)**
- **[Project Participation](#project-participation)**
  - [Contributing](#contributing)
  - [Security Vulnerability Reports](#security-vulnerability-reports)
  - [Bug reports](bug-reports)
  - [Feature Requests](#feature-requests)
  - [Code of Conduct](#code-of-conduct)

## Prerequisites

* AMD64: Python 3.7 (Recommended Python 3.7+)
* ARM64: Python 3.9+
* _Optional_ SNMP requires the Python library Scapy
* _Optional_ Samba module needs a working installation of Samba
* _Optional_ Portscan uses iptables (not nftables) and is only supported on Linux-based operating systems

## Features

* Mimic an array of network-accessible services for attackers to interact with.
* Receive various alerts as soon as potential threats are detected, highlighting the threat source IP address and where the breach may have occurred.

## Installation

The OpenCanary installation essentially involves ensuring the Python environment is ready, then installing the OpenCanary Python package (plus optional extras).

### Installation on Ubuntu

Installation on Ubuntu 20.04:
```
$ sudo apt-get install python3-dev python3-pip python3-virtualenv python3-venv python3-scapy libssl-dev libpcap-dev
$ virtualenv env/
$ . env/bin/activate
$ pip install opencanary
```

Optional extras (if you wish to use the Windows File Share module, and the SNMP module):
```
$ sudo apt install samba # if you plan to use the Windows File Share module
$ pip install scapy pcapy-ng # if you plan to use the SNMP module
```

### Installation on macOS

First, create and activate a new Python virtual environment:
```
$ virtualenv env/
$ . env/bin/activate
```

Macports users should then run:
```
$ sudo port install openssl
$ env ARCHFLAGS="-arch x86_64" LDFLAGS="-L/opt/local/lib" CFLAGS="-I/opt/local/include" pip install cryptography
```

Alternatively, Homebrew x86 users run:
````
$ brew install openssl
$ env ARCHFLAGS="-arch x86_64" LDFLAGS="-L/usr/local/opt/openssl/lib" CFLAGS="-I/usr/local/opt/openssl/include" pip install cryptography
````

Homebrew M1 users run:
```
$ brew install openssl
$ env ARCHFLAGS="-arch arm64" LDFLAGS="-L/opt/homebrew/opt/openssl@1.1/lib" CFLAGS="-I/opt/homebrew/opt/openssl@1.1/include" pip install cryptography
```

(The compilation step above is necessary as multiple OpenSSL versions may exist, which can confound the Python libraries.)

Now the installation can run as usual:
```
$ pip install opencanary
$ pip install scapy pcapy-ng # optional
```

The Windows File Share (smb) module is not available on macOS.

### Installation via Git

To install from source, instead of running pip do the following:

```
$ git clone https://github.com/thinkst/opencanary
$ cd opencanary
$ python setup.py sdist
$ cd dist
$ pip install opencanary-<version>.tar.gz
```

### Use via pkgx

OpenCanary is packaged via [pkgx](https://pkgx.sh/), so no installation is needed if pkgx is installed, simply preface the `opencanaryd` command with
`pkgx`. Due to environment variable protections in modern `sudo` implementations, the entire command must be run as root, or via `sudo -E`.

```
$ pkgx opencanaryd --version
```

### Installation for Docker

OpenCanary Docker images are hosted on Docker Hub. These are only useful on Linux Docker hosts, as the `host` network engine is required for accurate network information.

## Configuring OpenCanary

### Creating the initial configuration

When OpenCanary starts it looks for config files in the following locations and will stop when the first configuration is found:

1. `./opencanary.conf` (i.e. the directory where OpenCanary is installed)
2. `~/.opencanary.conf` (i.e. the home directory of the user, usually this will be `root` so `/root/.opencanary.conf`)
3. `/etc/opencanaryd/opencanary.conf`

To create an initial configuration, run as `root` (you may be prompted for a `sudo` password):
```
$ opencanaryd --copyconfig
[*] A sample config file is ready /etc/opencanaryd/opencanary.conf

[*] Edit your configuration, then launch with "opencanaryd --start"
```

This creates the path and file `/etc/opencanaryd/opencanary.conf`. You must now edit the config file to determine which services and logging options you want to enable.

### Enabling protocol modules and alerting

Configuration is performed via the JSON config file. Edit the file, and when happy save and exit.

### Optional modules

#### SNMP

The `snmp` module is only available when Scapy is present. See the installation steps for SNMP above.

#### Portscan

The `portscan` module is only available on Linux hosts, as it modifies `iptables` rules.

Please note that for the Portscan service, we have added a `portscan.ignore_localhost` setting, which means the OpenCanary `portscan` service will ignore (not alert on) port scans originating for the localhost IP (`127.0.0.1`). This setting is false by default.

#### Samba Setup

The Windows File Share module (`smb`) requires a Samba installation. See a step-by-step guide on [the Wiki](https://github.com/thinkst/opencanary/wiki/Opencanary-and-Samba).

## Running OpenCanary

OpenCanary is either run directly on a Linux or macOS host, or via a Docker container.

### Directly on Linux or macOS

Start OpenCanary by running:

```
$ . env/bin/activate
$ opencanaryd --start
```

### With pkgx

Start OpenCanary by running:

```
$ sudo -E pkgx opencanaryd --start
```

### With docker-compose

The route requires [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) to be installed.

> **Note**
> The portscan module is automatically disabled for Dockerised OpenCanary.

1. Edit the `data/.opencanary.conf` file to enable, disable or customize the services that will run.
1. Edit the `ports` section of the `docker-compose.yml` file to enable/disable the desired ports based on the services you have enabled in the config file.
1. Run the container.
    ```bash
    docker-compose up latest
    ```

To view the logs run `docker-compose logs latest`.

To stop the container run `docker-compose down`.

To build your own Docker OpenCanary using `docker compose`, head over to our [wiki](https://github.com/thinkst/opencanary/wiki/Using-Dockerised-OpenCanary#building-and-running-your-own-docker-opencanary-image-with-docker-compose)

### With Docker

Please head over our dedicated Docker [wiki](https://github.com/thinkst/opencanary/wiki/Using-Dockerised-OpenCanary#building-and-running-your-own-docker-opencanary-image-with-docker) for everything Dockerised OpenCanary.

### With Ansible

Please head over to our forked repository for an Ansible OpenCanary role over [here](https://github.com/thinkst/ansible-role-opencanary).
## Documentation

* The [Wiki](https://github.com/thinkst/opencanary/wiki) contains our FAQ.
* Additional documentation is available on our [main site](https://opencanary.org).

## Project Participation

### Contributing

We welcome PRs to this project. Please read our [Code of Conduct](https://github.com/thinkst/.github/blob/master/CODE_OF_CONDUCT.md) and [Contributing](https://github.com/thinkst/.github/blob/master/CONTRIBUTING.md) documents before submitting a pull request.

At a minimum you should run `pre-commit` before submitting the PR. Install and run it in the same Python environment that OpenCanary is installed into:
```
$ pip install pre-commit
# Do work
$ git add file
$ pre-commit
$ git add file # only run this if pre-commit auto-fixed the file
$ git commit
```

### Security Vulnerability Reports

See our [Security Policy](https://github.com/thinkst/opencanary/security/policy) for details on how to report security vulnerabilities.

### Bug reports

Please file bug reports on [Github](https://github.com/thinkst/opencanary/issues) using the template we provide.

### Feature Requests

Feature requests are tracked [here](https://github.com/thinkst/opencanary/discussions/categories/feature-requests).

### Code of Conduct

This project and everyone participating in it is governed by the
[Code of Conduct](https://github.com/thinkst/.github/blob/master/CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report unacceptable behavior
to github@thinkst.com.
