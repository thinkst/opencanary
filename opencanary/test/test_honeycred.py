import pytest

from opencanary import honeycred


@pytest.mark.parametrize(
    "username,expected",
    [
        ("alice", True),
        (b"alice", True),
        ("bob", False),
        (b"bob", False),
        (None, False),
        (b"\xff", False),
    ],
)
def test_username_honeycred_accepts_text_and_bytes(username, expected):
    assert honeycred.testCred({"username": "alice"}, username=username) is expected


@pytest.mark.parametrize("username", ["jos\u00e9", "jos\u00e9".encode("utf-8")])
def test_unicode_username_honeycred(username):
    assert honeycred.testCred({"username": "jos\u00e9"}, username=username)


@pytest.mark.parametrize("username", ["alice", b"alice", "bob", b"bob"])
@pytest.mark.parametrize("password", ["secret", b"secret", "wrong", b"wrong"])
def test_username_and_password_honeycred(username, password):
    credential = {
        "username": "alice",
        "password": honeycred.cryptcontext.handler("pbkdf2_sha512").hash("secret"),
    }
    expected = username in ("alice", b"alice") and password in ("secret", b"secret")
    assert honeycred.testCred(credential, username, password) is expected


@pytest.mark.parametrize("username", [None, "anyone", b"anyone"])
@pytest.mark.parametrize("password,expected", [("secret", True), ("wrong", False)])
def test_password_only_honeycred(username, password, expected):
    assert honeycred.testCred({"password": "secret"}, username, password) is expected


@pytest.fixture(scope="module", params=honeycred.cryptcontext.schemes())
def password_credential(request):
    return {"password": honeycred.cryptcontext.handler(request.param).hash("caf\u00e9")}


def test_missing_password_does_not_match(password_credential):
    assert honeycred.testCred(password_credential, password=None) is False


def test_invalid_utf8_password_does_not_match(password_credential):
    assert honeycred.testCred(password_credential, password=b"\xff") is False


@pytest.mark.parametrize(
    "password,expected",
    [("caf\u00e9", True), (b"caf\xc3\xa9", True), ("wrong", False), (b"wrong", False)],
)
def test_password_encodings(password_credential, password, expected):
    assert honeycred.testCred(password_credential, password=password) is expected


@pytest.mark.parametrize("password", ["", b""])
def test_empty_password_remains_matchable(password):
    assert honeycred.testCred({"password": ""}, password=password) is True


@pytest.mark.parametrize("scheme", ["pbkdf2_sha512", "bcrypt", "sha512_crypt"])
def test_raw_byte_password_matches_after_plaintext_nonmatch(scheme):
    password = b"\xffsecret"
    credentials = [
        {"password": "secret"},
        {"password": honeycred.cryptcontext.handler(scheme).hash(password)},
    ]
    hook = honeycred.buildHoneyCredHook(credentials)
    assert hook(password=password) is True
    assert hook(password=b"\xffwrong") is False


def test_missing_password_does_not_prevent_username_only_match():
    hook = honeycred.buildHoneyCredHook([{"password": "secret"}, {"username": "alice"}])
    assert hook(username="alice", password=None) is True
