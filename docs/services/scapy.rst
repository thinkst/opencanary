Scapy
================

Inside ~/.opencanary.conf:

.. code-block:: json

   {
       "scapy.enabled": true,
       "scapy.ports": [21, 22, 23, 80, 110, 139, 443, 445, 3306, 3389, 8080, 5900],
   }

this service can detect port scans on docker .

dont forget to add this when runing docker run :

--network host
