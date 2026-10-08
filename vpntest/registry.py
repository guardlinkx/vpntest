"""Discover check plugins and match them to catalog entries.

Importing by walking the package means adding a control is a new file plus a
catalog line; nothing registers itself by hand, so nothing gets forgotten.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Dict, List, Type

from .model import Check


def discover(package: str = "vpntest.checks") -> Dict[str, Type[Check]]:
    found: Dict[str, Type[Check]] = {}
    pkg = importlib.import_module(package)

    for mod in pkgutil.walk_packages(pkg.__path__, prefix=package + "."):
        module = importlib.import_module(mod.name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, Check) or obj is Check:
                continue
            if not getattr(obj, "id", ""):
                continue
            if obj.__module__ != mod.name:
                continue  # imported into another module, not defined there
            if obj.id in found and found[obj.id] is not obj:
                raise ValueError(f"Two checks claim id {obj.id}")
            found[obj.id] = obj
    return found


def coverage(registered: Dict[str, Type[Check]], catalog) -> Dict[str, List[str]]:
    """Which controls have code, and which code has no control."""
    have = set(registered)
    want = {c.id for c in catalog}
    return {
        "implemented": sorted(have & want),
        "catalog_without_check": sorted(want - have),
        "check_without_catalog": sorted(have - want),
    }
