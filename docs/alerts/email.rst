Email Alerts
============

To have an OpenCanary daemon directly send email alerts to edit the logger section of the *~/.opencanary.conf*. The file format is JSON.

In the configurations below, set these configuration variables:

* **mailhost** - The SMTP mail host and port.
* **fromaddr** - The from address. Usually does not have to exist.
* **toaddres** - An array of addresses that will receive the alert. Keep it short.
* **subject** - The email's subject.
* **credentials** - Optional parameter, if the SMTP server requires authentication.
* **secure** - Optional parameter if TLS support is mandatory or wanted.

More information can be found on the `PyLogger page <https://docs.python.org/2/library/logging.handlers.html#logging.handlers.SMTPHandler>`_.

Send to a Gmail address
-----------------------

.. code-block:: json

   // [..] # Services configuration
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

Depending on your ISP and their outbound spam protection mechanisms, you may need to send to TCP port 587, set up an `app password <https://support.google.com/accounts/answer/185833?hl=en>`_ and use credentials, as well as set an empty tuple for the **secure** parameter. Your configuration would then look like this:


.. code-block:: json

   // [..] # Services configuration
       "logger": {
       "class" : "PyLogger",
       "kwargs" : {
           "handlers": {
               "SMTP": {
                   "class": "logging.handlers.SMTPHandler",
                   "mailhost": ["smtp.gmail.com", 587],
                   "fromaddr": "noreply@yourdomain.com",
                   "toaddrs" : ["youraddress@gmail.com"],
                   "subject" : "OpenCanary Alert",
                   "credentials" : ["youraddress", "abcdefghijklmnop"],
                   "secure" : []
                }
            }
        }
    }

Send with SMTP authentication
-----------------------------

.. code-block:: json

   // [..] # Services configuration
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
                   "credentials" : ["myusername", "password1"],
		   "secure" : []
                }
            }
        }
    }

Environment Variables
---------------------

You can use environment variables in the configuration file to pass confidential information such as passwords or tokens from the host machine to the application.

For more information, see the [Configuration page](../starting/configuration.rst#environment-variables).
