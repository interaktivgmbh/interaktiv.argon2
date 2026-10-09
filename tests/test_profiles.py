from argon2 import extract_parameters
from AuthEncoding import AuthEncoding
from interaktiv.argon2 import ARGON2
from interaktiv.argon2 import DEFAULT_PROFILE
from interaktiv.argon2 import hash_password
from interaktiv.argon2 import needs_rehash
from interaktiv.argon2 import PROFILES

import pytest


PASSWORD = "Secret#123456"


def _parameters(hashed: bytes):
    return extract_parameters(hashed[len(b"{ARGON2}") :].decode())


@pytest.mark.parametrize(
    "profile,memory_mib,time_cost,parallelism",
    [
        ("rfc9106-low-memory", 64, 3, 4),
        ("owasp-46m", 46, 1, 1),
        ("owasp-19m", 19, 2, 1),
        ("owasp-12m", 12, 3, 1),
        ("owasp-9m", 9, 4, 1),
        ("owasp-7m", 7, 5, 1),
    ],
)
def test_profile_parameters(profile, memory_mib, time_cost, parallelism):
    params = PROFILES[profile]

    assert params.memory_cost == memory_mib * 1024
    assert params.time_cost == time_cost
    assert params.parallelism == parallelism


def test_pw_encrypt_uses_default_profile():
    hashed = AuthEncoding.pw_encrypt(PASSWORD, encoding=ARGON2)

    assert _parameters(hashed) == PROFILES[DEFAULT_PROFILE]


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_hash_password(profile):
    hashed = hash_password(PASSWORD, profile)

    assert hashed.startswith(b"{ARGON2}$argon2id$")
    assert _parameters(hashed) == PROFILES[profile]
    assert AuthEncoding.pw_validate(hashed, PASSWORD)


def test_hash_password_unknown_profile():
    """E.g. a profile that was removed in a later version."""
    hashed = hash_password(PASSWORD, "removed-profile")

    assert _parameters(hashed) == PROFILES[DEFAULT_PROFILE]


@pytest.mark.parametrize("scheme", ["SSHA", "SHA256", "SHA"])
def test_needs_rehash_legacy_schemes(scheme):
    assert needs_rehash(AuthEncoding.pw_encrypt(PASSWORD, encoding=scheme))


def test_needs_rehash_unprefixed_legacy_hash():
    assert needs_rehash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")


def test_needs_rehash_same_profile():
    assert not needs_rehash(hash_password(PASSWORD, "owasp-19m"), "owasp-19m")
    assert not needs_rehash(hash_password(PASSWORD, "owasp-19m").decode(), "owasp-19m")


def test_needs_rehash_other_profile():
    hashed = hash_password(PASSWORD, "owasp-19m")

    assert needs_rehash(hashed, DEFAULT_PROFILE)
    assert needs_rehash(hashed, "owasp-7m")


def test_hashes_of_every_profile_verify():
    """Hashes keep their own parameters, so switching never locks users out."""
    for profile in PROFILES:
        assert AuthEncoding.pw_validate(hash_password(PASSWORD, profile), PASSWORD)
