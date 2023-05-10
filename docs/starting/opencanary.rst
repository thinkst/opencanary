OpenCanary
==========

Getting Started
----------------

To get started create a virtual environment to play in:

.. code-block:: sh

   $ virtualenv env
   $ . env/bin/activate

Inside the virtualenv, install OpenCanary following the instructions in the `README <https://github.com/thinkst/opencanary>`_.

OpenCanary ships with a default config, which we'll copy and edit to get started. The config is a single `JSON <https://en.wikipedia.org/wiki/JSON>`_ dictionary.

.. code-block:: sh

   $ opencanaryd --copyconfig
   $ $EDITOR ~/.opencanary.conf

In the config file we'll change **device.node_id** which must be unique for
each instance of opencanaryd, and we'll configure **logger** to log
alerts to a file.

.. code-block:: json

    {
      "device.node_id": "Your-very-own-unique-name",
      // ...
      "logger": {
        "class": "PyLogger",
        "kwargs": {
          "handlers": {
            "file": {
              "class": "logging.FileHandler",
              "filename": "/var/tmp/opencanary.log"
            }
          }
        }
      }
      // ...
    }


With that in place, we can run the daemon and test that it logs a failed FTP login attempt to the log file.

.. code-block:: sh

   $ opencanaryd --start
   [...]
   $ ftp localhost
   [...]
   $ cat /var/tmp/opencanary.log
   [...]
   {"dst_host": "127.0.0.1", "dst_port": 21, "local_time": "2015-07-20 13:38:21.281259", "logdata": {"PASSWORD": "default", "USERNAME": "admin"}, "logtype": 2000, "node_id": "opencanary-0", "src_host": "127.0.0.1", "src_port": 49635}
   

Troubleshooting
---------------

The tool JQ can be used to check that the config file is well-formed JSON.

.. code-block:: sh

   $ jq . ~/.opencanary.conf

Run opencanaryd in the foreground to see more error messages.

.. code-block:: sh

   $ opencanaryd --dev

You may also easily restart the service using,

.. code-block:: sh

   $ opencanaryd --restart

