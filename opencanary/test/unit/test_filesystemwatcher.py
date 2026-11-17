import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("FileSystemWatcher requires Linux inotify", allow_module_level=True)

from opencanary.modules import FileSystemWatcher


class RecordingWatcher(FileSystemWatcher):
    def __init__(self, path):
        super().__init__(fileName=path)
        self.lines = []

    def handleLines(self, lines=None):
        self.lines.extend(line for line in lines or [] if line)


@pytest.fixture
def watcher(tmp_path):
    path = tmp_path / "audit.log"
    path.touch()
    watcher = RecordingWatcher(path)
    with path.open() as watcher.f:
        yield watcher


def test_appends_do_not_replay_previous_lines(watcher):
    watcher.path.write_text("first\n")
    watcher.processAuditLines()
    with watcher.path.open("a") as output:
        output.write("second\n")
    watcher.processAuditLines()
    watcher.processAuditLines()

    assert watcher.lines == ["first", "second"]


@pytest.mark.parametrize("replacement", ["", "after\n"])
def test_in_place_truncation_resumes_from_start(watcher, replacement):
    before = "a longer audit record before rotation"
    watcher.path.write_text(before + "\n")
    watcher.processAuditLines()

    watcher.path.write_text(replacement)
    watcher.processAuditLines()
    assert watcher.lines == [before] + replacement.splitlines()

    with watcher.path.open("a") as output:
        output.write("next\n")
    watcher.processAuditLines()
    assert watcher.lines == [before] + replacement.splitlines() + ["next"]

    # A second rotation must reset the offset again without replaying old lines.
    watcher.path.write_text("end\n")
    watcher.processAuditLines()
    watcher.processAuditLines()
    assert watcher.lines == [before] + replacement.splitlines() + ["next", "end"]
