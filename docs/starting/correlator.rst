Correlator
==========

Getting Started
---------------

To get started create a virtual environment to play in:

.. code-block:: sh

   $ virtualenv env
   $ . env/bin/activate

Inside the virtualenv, install OpenCanary Correlator following the instructions in the `README <https://github.com/thinkst/opencanary-correlator>`_.

The correlator runs with a default config, which we'll copy and edit to get started.

.. code-block:: sh

   $ opencanary-correlator
   Warning: no config file specified. Using the template config:
   /[...]/opencanary_correlator.conf
   $ cp /[...]/opencanary_correlator.conf opencanary-correlator.conf

In the config file, fill the Twilio or mandrill details (or both), and the notification addresses for both.

.. code-block:: json

   {
     "console.sms_notification_enable": true,
     "console.sms_notification_numbers": ["+336522334455"],
     "console.email_notification_enable": true,
     "console.email_notification_address": ["notifications@opencanary.org"],
     "console.slack_notification_enable": true,
     "console.slack_notification_webhook": ["https://hooks.slack.com/services/example/webhookdata"],
     "twilio.auth_token": "fae9206628714fb2ce00f72e94f2258f",
     "twilio.from_number": "+1201253234",
     "twilio.sid": "BD742385c0810b431fe2ddb9fc327c85ad",
     "console.mandrill_key": "9HCjwugWjibxww7kPFej",
     "scans.network_portscan_horizon": 1000
   }

With that in place, ensure that Redis is running and then run the correlator daemon.

.. code-block:: sh

   $ pgrep redis-server || echo 'Redis is not running!'
   $ opencanary-correlator --config=./opencanary-correlator.conf

To configure OpenCanary daemons to send their events to the correlator, edit the **logger** field in its config and restart the daemon to reload the config.

.. code-block:: json

  "logger": {
    "class": "PyLogger",
    "kwargs": {
      "handlers": {
        "json-tcp": {
          "class": "opencanary.logger.SocketJSONHandler",
          "host": "127.0.0.1",  // change to correlator IP
          "port": 1514
        }
      }
    }
  }


Troubleshooting
---------------

You can test that the Correlator alerts are working by sending an event directly to it (without using OpenCanary).

.. code-block:: sh

   echo '{"dst_host": "9.9.9.9", "dst_port": 21, "local_time": "2015-07-20 13:38:21.281259", "logdata": {"PASSWORD": "default", "USERNAME": "admin"}, "logtype": 2000, "node_id": "AlertTest", "src_host": "8.8.8.8", "src_port": 49635}' | nc -v localhost 1514

The tool `JQ <http://stedolan.github.io/jq/>`_ can be used to check that the config file is well-formed JSON.

.. code-block:: sh

   $ jq . ./opencanary-correlator.conf
