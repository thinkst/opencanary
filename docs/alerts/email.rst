Email Alerts
============

To have an OpenCanary daemon directly send email alerts edit the logger section of the *~/.opencanary.conf*. The file format is JSON.

In the configurations below, set these configuration variables:

* **mailhost** - The SMTP mailhost and port.
* **fromaddr** - The from address. Usually does not have to exist.
* **toaddres** - An array of addresses that will receive the alert. Keep it short.
* **subject** - The email's subject.
* **credentials** - Optional parameter, if the SMTP server requires authentication.

More information can be found on the `PyLogger page <https://docs.python.org/2/library/logging.handlers.html#logging.handlers.SMTPHandler>`_.

Send to a GMail address
-----------------------

.. code-block:: json

   [..] # Services configuration
       "logger": {
       "class" : "PyLogger",
       "kwargs" : {
           "handlers": {
               "SMTP": {
                   "class": "logging.handlers.SMTPHandler",
                   "mailhost": ["smtp.gmail.com", 25],
                   "fromaddr": "noreply@yourdomain.com",
                   "toaddrs" : ["youraddress@gmail.com"],
                   "subject" : "OpenCanary Alert"
                }
            }
        }
    }

Send with SMTP authentication
-----------------------------

.. code-block:: json

   [..] # Services configuration
       "logger": {
       "class" : "PyLogger",
       "kwargs" : {
           "handlers": {
               "SMTP": {
                   "class": "logging.handlers.SMTPHandler",
                   "mailhost": ["authenticated.mail.server", 25],
                   "fromaddr": "canary@yourdomain.com",
                   "toaddrs" : ["youraddress@yourdomain.com"],
                   "subject" : "OpenCanary Alert",
                   "credentials" : ["myusername", "password1"]
                }
            }
        }
    }
