HPFeeds
========

OpenCanary can be used directly (without the Correlator) with daemons supporting the `hpfeeds <https://github.com/rep/hpfeeds>`_ protocol.

To enable hpfeeds add the following to the logging section of settings.json:

.. code-block:: json

    "hpfeeds": {
        "class": "opencanary.logger.HpfeedsHandler",
        "host": "127.0.0.1",
        "port": 10000,
        "ident": "test",
        "secret":"12345",
        "channels":["test.events"]
    }
