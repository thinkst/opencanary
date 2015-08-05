OpenCanary
=================
Thinkst Applied Research

Overview
----------

OpenCanary is a daemon that runs several canary versions of services that alerts when a service is (ab)used.

Prerequisites
----------------

* Python 2.7
* [Optional] SNMP requires the python library scapy
* [Optional] RDP requires the python library rdpy
* [Optional] Samba module needs a working installation of samba

Install
----------

Installation on Ubuntu:

```
$ sudo apt-get install python-dev python-pip python-virtualenv
$ virtualenv venv/
$ . venv/bin/activate
$ pip install opencanary
$ pip install scapy pcapy # optional
```

Installation OS X needs an extra step, as multiple OpenSSL versions
may exist which confounds the python libraries using to it.

```
$ virtualenv venv/
$ . venv/bin/activate
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
$ python setup.py install
```

Run
----

OpenCanary is started by running:

```
$ sudo /path/to/venv/bin/opencanary --start
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
       syslog only = yes
       syslog = 0
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
