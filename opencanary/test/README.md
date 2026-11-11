# Running tests

From the repository root:

```sh
uv sync --locked --dev
uv run pytest
```

The default suite is `opencanary/test/unit`. It runs against the checkout without
starting OpenCanary, opening listening sockets, or reading a machine's OpenCanary
configuration or `/var/tmp/opencanary.log`. Protocol tests use Twisted's
`StringTransport` and `Clock`; assertions inspect responses and captured events.
No root privileges are needed. Do not run `uv` or `pytest` with `sudo`.

## Integration tests

```sh
uv run pytest opencanary/test/integration
# Both suites:
uv run pytest opencanary/test
# One test:
uv run pytest opencanary/test/integration/test_ftp.py::test_authenticated_ftp
```

Integration tests use real protocol clients. The `canary` fixture starts only the
requested services in a fresh subprocess for each test, using the checkout and
the test configuration in `integration/opencanary.conf`. It binds loopback ports
allocated by the OS, waits for listeners to start, and supplies their addresses
to the clients. Configuration, SSH/TLS keys, events, and process output live in
pytest's temporary directory. The fixture stops and reaps the process even when
the test or startup fails; no installed/running daemon or system log is needed.
The Git integration test also requires the `git` executable.

Startup/event failures include child-process output. Event assertions poll for a
specific matching event with a deadline, rather than assuming the last line of a
shared log belongs to the test. Tests must not depend on another test's actions.

CI runs both suites separately on its Python/OS matrix. Tests requiring external
Samba, firewall rules, or other privileged system facilities are not part of
these suites; do not add such dependencies to default test discovery.

## Adding tests

- Put in-memory behavior tests in `unit/`, without integration-client imports.
- Put real-client tests in `integration/`. Request `canary("ftp")` (or another
  supported module) and use the returned `host`, `port`, and `url`, never fixed
  ports or global logs. `canary("mongodb", "vnc")` starts both on the same reactor;
  additional listener ports are available through `server.ports`.
- Record `start = server.get_log_count()` before the action, then use
  `server.get_matching_log(start, predicate)` to inspect its event.
- Use bounded network timeouts and close clients. Use `tmp_path` for test files.
- Use platform skips only for genuinely platform-specific behavior, such as
  Linux inotify, not to hide unavailable services or failed fixture startup.
