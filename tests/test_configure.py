"""Plone loads the ZCML of this package at startup, which registers the scheme."""

from importlib.metadata import entry_points
from pathlib import Path
from xml.etree import ElementTree

import interaktiv.argon2


def test_autoinclude_entry_point():
    plugins = entry_points(group="z3c.autoinclude.plugin")
    targets = {ep.value for ep in plugins if ep.dist.name == "interaktiv.argon2"}

    assert targets == {"plone"}


def test_configure_zcml():
    path = Path(interaktiv.argon2.__file__).parent / "configure.zcml"

    root = ElementTree.parse(path).getroot()  # noqa: S314 (own package file)

    assert root.tag == "{http://namespaces.zope.org/zope}configure"
