import runpy
import warnings
from pathlib import Path

import opencanary.config
import opencanary.logger
from opencanary import __version__

TAC_PATH = Path(__file__).resolve().parents[3] / "bin" / "opencanary.tac"


class StartupTestConfig:
    def checkValues(self):
        return []

    def moduleEnabled(self, module_name):
        return False


class StartupTestLogger:
    def __init__(self):
        self.events = []

    def log(self, event, retry=True):
        self.events.append(event)


def test_startup_message_includes_version(monkeypatch):
    logger = StartupTestLogger()
    monkeypatch.setattr(opencanary.config, "Config", StartupTestConfig)
    monkeypatch.setattr(opencanary.logger, "getLogger", lambda config: logger)
    monkeypatch.setattr(warnings, "warn", warnings.warn)

    runpy.run_path(str(TAC_PATH))

    assert logger.events[-1]["logdata"]["msg"]["logdata"] == (
        "Canary running!!! (OpenCanary version %s)" % __version__
    )
