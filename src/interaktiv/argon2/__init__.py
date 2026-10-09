"""Argon2id password hashing scheme for AuthEncoding.

Importing this package registers an ``ARGON2`` scheme with AuthEncoding, so
Zope and Plone can verify passwords stored as
``{ARGON2}$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>``. ``argon2-cffi``
generates a random salt per hash and stores it, together with the cost
parameters, inside the hash string.

The registration only lives in the memory of the running process, nothing is
stored in the database. Plone imports this package at startup through its
``z3c.autoinclude`` entry point. Keep it installed as long as passwords are
stored as Argon2id hashes, otherwise these users cannot log in.
"""

from argon2 import PasswordHasher
from argon2 import profiles
from argon2.exceptions import InvalidHashError
from argon2.exceptions import VerificationError
from AuthEncoding import AuthEncoding
from dataclasses import replace

import logging


__version__ = "1.0.0"

PACKAGE_NAME = "interaktiv.argon2"

logger = logging.getLogger(PACKAGE_NAME)

ARGON2 = "ARGON2"
ARGON2_PREFIX = f"{{{ARGON2}}}".encode("ascii")

_OWASP = replace(profiles.RFC_9106_LOW_MEMORY, parallelism=1)

# Equally strong cost profiles: less memory is compensated by more iterations.
# see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
PROFILES = {
    "rfc9106-low-memory": profiles.RFC_9106_LOW_MEMORY,  # 64 MiB, t=3, p=4
    "owasp-46m": replace(_OWASP, memory_cost=46 * 1024, time_cost=1),
    "owasp-19m": replace(_OWASP, memory_cost=19 * 1024, time_cost=2),
    "owasp-12m": replace(_OWASP, memory_cost=12 * 1024, time_cost=3),
    "owasp-9m": replace(_OWASP, memory_cost=9 * 1024, time_cost=4),
    "owasp-7m": replace(_OWASP, memory_cost=7 * 1024, time_cost=5),
}

DEFAULT_PROFILE = "rfc9106-low-memory"

_hashers = {name: PasswordHasher.from_parameters(p) for name, p in PROFILES.items()}


def _to_str(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def _hasher(profile: str) -> PasswordHasher:
    """The hasher of a profile, the default one for unknown profiles."""
    return _hashers.get(profile, _hashers[DEFAULT_PROFILE])


def hash_password(password: str | bytes, profile: str = DEFAULT_PROFILE) -> bytes:
    """Hash a password with the given profile, including the ``{ARGON2}``
    prefix, as AuthEncoding stores it.
    """
    return ARGON2_PREFIX + _hasher(profile).hash(_to_str(password)).encode("ascii")


def needs_rehash(reference: str | bytes, profile: str = DEFAULT_PROFILE) -> bool:
    """Check whether a stored password hash should be replaced.

    True for every hash that is not Argon2 (e.g. SSHA, SHA256 or legacy
    formats) and for Argon2 hashes created with other parameters than the
    given profile.
    """
    if isinstance(reference, str):
        reference = reference.encode("utf-8")

    if not reference.startswith(ARGON2_PREFIX):
        return True

    return _hasher(profile).check_needs_rehash(reference[len(ARGON2_PREFIX) :])


class Argon2HashingScheme:
    """An Argon2id hashing scheme for AuthEncoding.

    ``AuthEncoding.pw_encrypt(password, encoding="ARGON2")`` uses the default
    profile. To hash with another profile, use ``hash_password``.
    """

    def encrypt(self, pw: str | bytes) -> bytes:
        return _hasher(DEFAULT_PROFILE).hash(_to_str(pw)).encode("ascii")

    def validate(self, reference: bytes, attempt: str | bytes) -> bool:
        # verification reads the cost parameters from the hash itself, so
        # any of the hashers can verify hashes of every profile
        try:
            return _hasher(DEFAULT_PROFILE).verify(_to_str(reference), _to_str(attempt))
        except (VerificationError, InvalidHashError):
            return False


def register_scheme() -> None:
    """Register the ARGON2 scheme with AuthEncoding (once)."""
    if ARGON2 not in AuthEncoding.listSchemes():
        AuthEncoding.registerScheme(ARGON2, Argon2HashingScheme())


register_scheme()
