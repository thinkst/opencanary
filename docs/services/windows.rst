Windows Server
================

The Samba and RDP modules require an extra installation step. It's a
good idea to consult the `README <https://github.com/thinkst/opencanary>`_ before trying this out.

Inside ~/.opencanary.conf:

.. code-block:: json

   {
       "smb.auditfile": "/var/log/samba-audit.log",
       "smb.enabled": true
   }

Below is an example of an `smb.conf` for a Samba installation,

.. code-block:: dosini

        [global]
            workgroup = WORKGROUP
            server string = NBDocs
            netbios name = SRV01
            dns proxy = no
            log file = /var/log/samba/log.all
            log level = 0
            max log size = 100
            panic action = /usr/share/samba/panic-action %d
            server role = standalone
            passdb backend = tdbsam
            obey pam restrictions = yes
            unix password sync = no
            map to guest = bad user
            usershare allow guests = yes
            load printers = no
            vfs object = full_audit
            full_audit:prefix = %U|%I|%i|%m|%S|%L|%R|%a|%T|%D
            full_audit:success = flistxattr
            full_audit:failure = none
            full_audit:facility = local7
            full_audit:priority = notice
        [myshare]
            comment = All the stuff!
            path = /samba
            guest ok = yes
            read only = yes
            browseable = yes

Please note that there are some details in the above config that you would want to change,

* server string
* NetBIOS name
* [myshare] to the name of your share
* path

Of course, you may change other settings as long as the `smbd_audit` logs to the file that your
OpenCanary daemon is watching (above we set it as `/var/log/samba-audit.log`).

In the above config, we are relying on Samba using Syslog (rsyslog in newer systems). For our Samba
to use rsyslog, we will edit the `/etc/rsyslog.conf` file. Below are two lines we add to the bottom,

.. code-block:: unixconfig

    $FileCreateMode 0644
    local7.*            /var/log/samba-audit.log

This will redirect any message of facility local7 to your `/var/log/samba-audit.log` file, which will be
watched by our OpenCanary daemon.

Please note this is all written up in the GitHub Wiki.
