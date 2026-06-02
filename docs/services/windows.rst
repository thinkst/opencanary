Windows Server
================

The Windows File Share module runs a pure Python SMB server using impacket. It does
not require Samba to be installed. RDP still requires its usual extra setup.

Inside ~/.opencanary.conf:

.. code-block:: json

   {
       "smb.enabled": true,
       "smb.port": 445,
       "smb.share_name": "myshare",
       "smb.server_name": "SRV01",
       "smb.auth_mode": "guest"
   }

By default OpenCanary exposes a guest-accessible, read-only share backed by a
small packaged sample directory. You can change the visible share name and server
name with ``smb.share_name`` and ``smb.server_name``. To serve a different
read-only directory, set ``smb.share_path`` to an existing directory.

To require NTLM credentials before the share can be mounted, switch the auth mode
and provide either a password or NTLM hashes:

.. code-block:: json

   {
       "smb.auth_mode": "ntlm",
       "smb.ntlm_username": "filesvc",
       "smb.ntlm_password": "ChangeMe123"
   }

Instead of ``smb.ntlm_password`` you can provide ``smb.ntlm_hashes`` in
``LMHASH:NTHASH`` format, or ``smb.ntlm_nthash`` with optional
``smb.ntlm_lmhash``.

Binding to TCP port 445 normally requires root or equivalent privileges. For
development or unprivileged deployments, set ``smb.port`` to a high port such as
1445 and connect to that port explicitly.
