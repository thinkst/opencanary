import git
import pytest

from opencanary.logger import LoggerBase


def test_git_clone_is_rejected_and_logged(canary, tmp_path):
    service = canary("git")
    start = service.get_log_count()
    host = f"{service.host}:{service.port}"

    with pytest.raises(git.exc.GitCommandError):
        git.Repo.clone_from(
            f"git://{host}/test.git", tmp_path / "repository", kill_after_timeout=5
        )

    log = service.get_matching_log(
        start,
        lambda event: event.get("logtype") == LoggerBase.LOG_GIT_CLONE_REQUEST
        and event.get("dst_port") == service.port
        and event.get("logdata", {}).get("REPO") == "test.git",
    )
    assert log is not None
    # Git may append protocol negotiation fields after the NUL-delimited host.
    assert log["logdata"]["HOST"].split("\0", 1)[0] == host
