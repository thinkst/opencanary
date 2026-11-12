# Running tests

From the repository root:

```sh
uv sync --locked --dev
# Unit tests:
uv run pytest
# Integration tests:
uv run pytest opencanary/test/integration
# Both suites:
uv run pytest opencanary/test
# One test:
uv run pytest opencanary/test/integration/test_ftp.py::test_authenticated_ftp
```

## Adding tests

- Put in-memory behavior tests in `unit/`, without integration-client imports.
- Put real-client tests in `integration/`. Request `canary("ftp")` (or another
  supported module) and use the returned `host`, `port`, and `url`, never fixed
  ports or global logs. `canary("mongodb", "vnc")` starts both on the same reactor;
  additional listener ports are available through `server.ports`.
