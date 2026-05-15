pytest assumes that OpenCanary has been installed and is running.

In particular it assumes that OpenCanary is logging to /var/tmp/opencanary.log
and that the services it's testing are enabled.

It would be much better to setup tests to start the services needed and provide
the configuration files so that tests can be run without needing to reinstall
and start the service before each test. It would also be better to be able to
test the code directly rather than relying on the output of logs.

Still this is a start.
