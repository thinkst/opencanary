import functools
from passlib.context import CryptContext

__all__ = ["buildHoneyCredHook", "cryptcontext"]

cryptcontext = CryptContext(
    schemes=["pbkdf2_sha512", "bcrypt", "sha512_crypt", "plaintext"]
)


def buildHoneyCredHook(creds):
    return functools.partial(testManyCreds, creds)


def testCred(cred, username=None, password=None):
    """
    Test if given credentials matches specified credentials

    If specified credentials doesn't have username or password, it
    will still match on the other.

    """
    cred_username = cred.get("username", None)
    cred_password = cred.get("password", None)

    user_match = True
    if cred_username is not None:
        if isinstance(username, str):
            username = username.encode("utf-8")
        user_match = cred_username.encode("utf-8") == username

    password_match = True
    if cred_password is not None:
        if password is None:
            return False
        try:
            password_match = cryptcontext.verify(password, cred_password)
        except UnicodeDecodeError:
            return False

    return user_match and password_match


def testManyCreds(creds, username=None, password=None):
    for c in creds:
        if testCred(c, username, password):
            return True
    return False
