Windows Server
================

The Samba and RDP modules require an extra installation steps. It's a
good idea to consult the `README <https://github.com/thinkst/opencanary>`_ before trying this out.

Inside ~/.opencanary.conf:

.. code-block:: json

   {
       "smb.auditfile": "/var/log/samba-audit.log",
       "smb.configfile": "/etc/samba/smb.conf",
       "smb.domain": "corp.thinkst.com",
       "smb.enabled": true,
       "smb.filelist": [
          {  
               "name": "2016-Tender-Summary.pdf",
               "type": "PDF"
          },
          {
            "name": "passwords.docx",
            "type": "DOCX"
          }
       ],
       "smb.mode": "workgroup",
       "smb.netbiosname": "FILESERVER",
       "smb.serverstring": "Windows 2003 File Server",
       "smb.sharecomment": "Office documents",
       "smb.sharename": "Documents",
       "smb.sharepath": "/changeme",
       "smb.workgroup": "OFFICE",
       "rdp.enabled": true,
       "rdp.port", 3389,
       [..] # logging configuration
   }

