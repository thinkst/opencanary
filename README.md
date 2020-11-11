OpenCanary
=================
Thinkst Applied Research

![opencanary logo](docs/logo.png)

Overview
----------

In essence, OpenCanary creates a network honeypot allowing you to catch hackers before they fully compromise your systems. As a technical definition, OpenCanary is a daemon that runs several canary versions of services that alerts when a service is (ab)used. 

Features
----------

* Receive email alerts as soon as potential threats are detected, highlighting the threat source IP address and where the breach may have taken place. 

Prerequisites
----------------

* Python 2.7, 3.6 
* [Optional] SNMP requires the python library scapy
* [Optional] RDP requires the python library rdpy
* [Optional] Samba module needs a working installation of samba

Installation
----------

For updated and cleaner documentation, please head over to http://opencanary.org

Installation on Ubuntu:

```
$ sudo apt-get install python-dev python-pip python-virtualenv
$ virtualenv env/
$ . env/bin/activate
$ pip install opencanary
$ pip install scapy pcapy # optional
```

Ubuntu users installing rdpy should run the following before installing OpenCanary:

```
$ sudo apt-get install -y build-essential libssl-dev libffi-dev python-dev
$ pip install rdpy
```

Installation OS X needs an extra step, as multiple OpenSSL versions
may exist which confounds the python libraries using to it.

```
$ virtualenv env/
$ . env/bin/activate
```

Macports users should then run:
```
$ sudo port install openssl
$ env ARCHFLAGS="-arch x86_64" LDFLAGS="-L/opt/local/lib" CFLAGS="-I/opt/local/include" pip install cryptography
```

Alternatively homebrew users run:
````
$ brew install openssl
$ env ARCHFLAGS="-arch x86_64" LDFLAGS="-L/usr/local/opt/openssl/lib" CFLAGS="-I/usr/local/opt/openssl/include" pip install cryptography
````

Now installation can run as usual:
```
$ pip install opencanary
$ pip install scapy pcapy # optional
```

To install from source, instead of running pip do the following:

```
$ git clone https://github.com/thinkst/opencanary
$ cd opencanary
$ python setup.py sdist
$ cd dist
$ pip install opencanary-<version>.tar.gz
```

If you are looking to get OpenCanary working on OpenBSD, take a look at https://github.com/8com/opencanary.

Run
----

OpenCanary is started by running:

```
$ . env/bin/activate
$ opencanaryd --start
```

On the first run, instructions are printed that will get to a working config.


Samba Setup (optional)
----------------------

The Samba OpenCanary module monitors a log file produced by the Samba
full_audit VFS module. Setup relies on:

* Having Samba installed.
* A modified Samba config file, to write file events to syslog's LOCAL7 facility.
* A modified syslog file, to output LOCAL7 to a samba-audit.log file.

As template Samba config, modify the following and install it to the
right location (often /etc/samba/smb.conf). The lines you'll likely
want to change are:

* path
* workgroup
* server string
* netbios name
* [myshare]
* comment


```
    [global]
       workgroup = WORKGROUP
       server string = blah
       netbios name = SRV01
       dns proxy = no
       log file = /var/log/samba/log.all
       log level = 0
       vfs object = full_audit
       full_audit:prefix = %U|%I|%i|%m|%S|%L|%R|%a|%T|%D
       full_audit:success = pread
       full_audit:failure = none
       full_audit:facility = local7
       full_audit:priority = notice
       max log size = 100
       panic action = /usr/share/samba/panic-action %d

       #samba 4
       server role = standalone server

       #samba 3
       #security = user

       passdb backend = tdbsam
       obey pam restrictions = yes
       unix password sync = no
       map to guest = bad user
       usershare allow guests = yes
    [myshare]
       comment = All the stuff!
       path = /home/demo/share
       guest ok = yes
       read only = yes
       browseable = yes
       #vfs object = audit
```

Configure syslog to write the Samba logs out to the file that
OpenCanary monitors. With rsyslog, adding these two lines to
/etc/rsyslog will do that:

```
$FileCreateMode 0644
local7.*            /var/log/samba-audit.log
```

For other syslog implementations similar lines might work.

Docker
----------------

To build the latest Docker image (based on the code on a given branch) run:

```bash
docker build -t opencanary -f Dockerfile.latest .
```

To build a Docker image based on what has been released in Pypi, run:

```bash
docker build -t opencanary -f Dockerfile.stable .
```

### Docker Compose 

