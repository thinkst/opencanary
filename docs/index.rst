OpenCanary
===========

Welcome to the OpenCanary guide.

OpenCanary is a daemon that runs canary services, which trigger alerts
when (ab)used. The alerts can be sent to a variety of sources,
including syslog, emails and a companion daemon opencanary-correlator.

The Correlator coalesces multiple related events (eg. individual
brute-force login attempts) into a single alert sent via email or
SMS.


.. _getting-started:

Getting Started
---------------

The first section will get you quickly up and running with canary
services sending alerts.

.. toctree::
   :maxdepth: 1

   starting/opencanary
   starting/correlator

Services
---------

Try these out in the OpenCanary configs for more typical server personalities.

.. toctree::
   :maxdepth: 1

   services/webserver
   services/windows
   services/mysql
   services/mssql


Alerting
---------

:ref:`getting-started` walks through two different ways to configure alerting: logging directly to a file, and sending alerts to the Correlator for email and SMS alerts. Other possibilities are below:

.. toctree::
   :maxdepth: 2

   alerts/email

Indices and tables
------------------
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
