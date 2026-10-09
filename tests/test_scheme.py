from AuthEncoding import AuthEncoding
from interaktiv.argon2 import ARGON2
from interaktiv.argon2 import register_scheme


PASSWORD = "Secret#123456"


def test_scheme_registered_on_import():
    assert ARGON2 in AuthEncoding.listSchemes()


def test_register_scheme_idempotent():
    register_scheme()
    register_scheme()

    assert AuthEncoding.listSchemes().count(ARGON2) == 1


def test_encrypt_uses_argon2id():
    hashed = AuthEncoding.pw_encrypt(PASSWORD, encoding=ARGON2)

    assert hashed.startswith(b"{ARGON2}$argon2id$")
    assert AuthEncoding.is_encrypted(hashed)


def test_encrypt_is_salted():
    """The same password must never produce the same hash."""
    first = AuthEncoding.pw_encrypt(PASSWORD, encoding=ARGON2)
    second = AuthEncoding.pw_encrypt(PASSWORD, encoding=ARGON2)

    assert first != second


def test_validate():
    hashed = AuthEncoding.pw_encrypt(PASSWORD, encoding=ARGON2)

    assert AuthEncoding.pw_validate(hashed, PASSWORD)
    assert AuthEncoding.pw_validate(hashed, PASSWORD.encode())
    assert not AuthEncoding.pw_validate(hashed, "wrong")


def test_validate_str_reference():
    hashed = AuthEncoding.pw_encrypt(PASSWORD, encoding=ARGON2).decode()

    assert AuthEncoding.pw_validate(hashed, PASSWORD)


def test_validate_non_ascii_password():
    password = "Pässwörd#123€"
    hashed = AuthEncoding.pw_encrypt(password, encoding=ARGON2)

    assert AuthEncoding.pw_validate(hashed, password)


def test_validate_long_password():
    """Unlike bcrypt, argon2 uses the whole password, not only 72 bytes."""
    password = "a" * 100 + "B1#"
    hashed = AuthEncoding.pw_encrypt(password, encoding=ARGON2)

    assert AuthEncoding.pw_validate(hashed, password)
    assert not AuthEncoding.pw_validate(hashed, "a" * 100 + "B2#")


def test_validate_corrupt_hash():
    assert not AuthEncoding.pw_validate(b"{ARGON2}not-a-hash", PASSWORD)


def test_other_schemes_still_validate():
    for scheme in ("SSHA", "SHA256"):
        hashed = AuthEncoding.pw_encrypt(PASSWORD, encoding=scheme)
        assert AuthEncoding.pw_validate(hashed, PASSWORD)
