import pytest
import git

from helpers import get_last_log


@pytest.fixture
def git_repo():
    repo = git.Repo
    yield repo


def test_clone_a_repository(git_repo):
    with pytest.raises(git.exc.GitCommandError):
        git_repo.clone_from("git://localhost/test.git", "/tmp/git_test")


def test_log_git_clone(git_repo):
    """
    Check that the git clone attempt was logged
    """
    # This test assumes a prior clone attempt has already been made.
    # Otherwise, trigger one here or in shared test setup.
    last_log = get_last_log()
    assert "localhost" in last_log["logdata"]["HOST"]
    assert last_log["logdata"]["REPO"] == "test.git"
