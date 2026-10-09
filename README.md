# interaktiv.argon2

Argon2id password hashing for Zope and Plone.

`interaktiv.argon2` registers an `ARGON2` scheme with [AuthEncoding](https://pypi.org/project/AuthEncoding/), the library Zope and Plone use to hash and verify passwords.
With the scheme registered, every user manager of Zope and Plone can verify passwords stored as Argon2id hashes:

```text
{ARGON2}$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
```

The package is a plain Python library, not a Plone add-on.
It has no installation profile, and it never writes anything to the database.

[interaktiv.passwordpolicy](https://github.com/interaktivgmbh/interaktiv.passwordpolicy) uses it to store passwords as Argon2id hashes.

## Keep this package installed

The scheme is required to verify Argon2id hashes.
If you remove `interaktiv.argon2` while passwords are stored as Argon2id hashes, these users can no longer log in until they reset their password using their recovery email.

This also applies when you remove `interaktiv.passwordpolicy`.
Your package manager removes `interaktiv.argon2` together with it, unless you list `interaktiv.argon2` in the dependencies of your project:

```toml
dependencies = [
    "interaktiv.argon2",
]
```

## How the registration works

AuthEncoding keeps its schemes in a list in the memory of the running process.
Importing `interaktiv.argon2` adds the `ARGON2` scheme to that list.
To verify a password, AuthEncoding picks the scheme by the prefix of the stored hash, `{ARGON2}`.

Plone imports the package at startup, because it loads the `configure.zcml` of every installed package with a `z3c.autoinclude` entry point for `plone`.
The `configure.zcml` of this package is empty, loading it only imports the package.
In plain Zope, add `<include package="interaktiv.argon2" />` to your ZCML, or import the package.

## Usage

`AuthEncoding` hashes with the default profile:

```python
from AuthEncoding import AuthEncoding

hashed = AuthEncoding.pw_encrypt("secret", encoding="ARGON2")
AuthEncoding.pw_validate(hashed, "secret")
```

To hash with another cost profile, and to check whether a stored hash uses the current profile:

```python
from interaktiv.argon2 import hash_password
from interaktiv.argon2 import needs_rehash

hashed = hash_password("secret", "owasp-19m")
needs_rehash(hashed, "owasp-19m")
```

## Cost profiles

| Profile | Memory | Iterations | Lanes | Source |
|---|---|---|---|---|
| `rfc9106-low-memory` (default) | 64 MiB | 3 | 4 | [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-4), second recommended option |
| `owasp-46m` | 46 MiB | 1 | 1 | [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id) |
| `owasp-19m` | 19 MiB | 2 | 1 | OWASP |
| `owasp-12m` | 12 MiB | 3 | 1 | OWASP |
| `owasp-9m` | 9 MiB | 4 | 1 | OWASP |
| `owasp-7m` | 7 MiB | 5 | 1 | OWASP |

Every hash stores its own salt and cost parameters, so hashes of all profiles stay valid when you change the profile.

## Development

The package does not depend on Plone, so you can test it without a Plone installation.

```shell
uv run --extra test pytest
uvx ruff format --check .
uvx ruff check .
```

## License

The project is licensed under GPLv2.
