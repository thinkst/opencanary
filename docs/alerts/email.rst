Email Alerts
============

To have an OpenCanary daemon directly send email alerts edit the logger section of the *~/.opencanary.conf*.

.. code-block:: json

   [..] # Services configuration
       "logger": {
	"class" : "PyLogger",
	"kwargs" : {
	    "handlers": {
		"SMTP": {
		    "class": "logging.SMTPHandler",
		    "mailhost": ["localhost", 25],
		    "fromaddr": "",
		    "toaddrs" : [],
		    "subject" : "OpenCanary Alert",
		    "credentials" : ["myusername", "password1"],
		}
	    }
	}
    }
   
