"""Integration tests own their listeners, configuration, keys, logs, and process."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import pytest

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parents[2]


class Canary:
    host = "127.0.0.1"

    def __init__(self, process, directory, name):
        self.process = process
        self.directory = directory
        self.name = name
        self.ports = {}

    @property
    def port(self):
        return self.ports[self.name]

    @property
    def url(self):
        scheme = "https" if self.name == "https" else "http"
        return f"{scheme}://{self.host}:{self.port}"

    def diagnostics(self):
        return (self.directory / "process.log").read_text()

    def wait_ready(self):
        ready = self.directory / "ready.json"
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                pytest.fail(
                    f"Canary process exited during startup:\n{self.diagnostics()}"
                )
            if ready.exists():
                self.ports = json.loads(ready.read_text())
                return
            time.sleep(0.02)
        pytest.fail(f"Canary listeners did not start within 20s:\n{self.diagnostics()}")

    def logs(self):
        # Only parse complete records: the child may be writing the last line.
        lines = (self.directory / "events.jsonl").read_text().splitlines(keepends=True)
        return [json.loads(line) for line in lines if line.endswith("\n")]

    def get_log_count(self):
        return len(self.logs())

    def get_matching_log(self, start_line, predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            for event in reversed(self.logs()[start_line:]):
                if predicate(event):
                    return event
            if self.process.poll() is not None:
                pytest.fail(
                    f"Canary process exited while waiting for an event:\n{self.diagnostics()}"
                )
            time.sleep(0.01)
        pytest.fail(
            f"No matching event within 5s. Events: {self.logs()[start_line:]!r}\n"
            f"Process output:\n{self.diagnostics()}"
        )

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


@pytest.fixture
def canary(tmp_path, request):

    def start(name, *additional_names):
        names = (name, *additional_names)
        directory = Path(tempfile.mkdtemp(prefix="canary-", dir=tmp_path))
        settings = json.loads((CURRENT_DIR / "opencanary.conf").read_text())
        # Port zero lets the listener itself allocate a free port, with no
        # bind-close-rebind race. Do not run production fixed-port validation.
        for key in settings:
            if key.endswith(".port"):
                settings[key] = 0
        settings["device.listen_addr"] = "127.0.0.1"
        settings["https.certificate"] = str(directory / "tls.pem")
        settings["https.key"] = str(directory / "tls.key")
        settings["ssh.key_path"] = str(directory)
        settings["logger"]["kwargs"]["handlers"] = {
            "file": {
                "class": "logging.FileHandler",
                "filename": str(directory / "events.jsonl"),
                "formatter": "plain",
            }
        }
        config_path = directory / "opencanary.conf"
        config_path.write_text(json.dumps(settings))
        (directory / "events.jsonl").touch()
        environment = dict(os.environ, PYTHONPATH=str(ROOT_DIR), HOME=str(directory))
        # Keep the reactor independent of blocking clients and disposable per test.
        # A subprocess also lets teardown kill a server whose reactor is blocked.
        with (directory / "process.log").open("w") as output:
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(CURRENT_DIR / "opencanary_runner.py"),
                    str(config_path),
                    str(directory / "ready.json"),
                    *names,
                ],
                cwd=directory,
                env=environment,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
        instance = Canary(process, directory, name)
        # Register before readiness checks so failed startups also get cleaned up.
        request.addfinalizer(instance.stop)
        instance.wait_ready()
        return instance

    return start
