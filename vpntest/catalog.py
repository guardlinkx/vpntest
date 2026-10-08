"""Controls as data.

A check is only allowed to run if its id appears here, so every finding can be
traced to a named baseline. Adding a control is a YAML entry plus a plugin
file — the runner never changes.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

import yaml

from .model import Severity


@dataclass
class Control:
    id: str
    protocol: str
    title: str
    requirement: str
    baselines: List[str]
    severity: Severity = Severity.MEDIUM
    remediation: str = ""
    notes: str = ""


class Catalog:
    def __init__(self, controls: Dict[str, Control]):
        self._controls = controls

    @classmethod
    def load(cls, directory: str) -> "Catalog":
        controls: Dict[str, Control] = {}
        files = sorted(glob.glob(os.path.join(directory, "*.yaml")))
        if not files:
            raise FileNotFoundError(f"No catalog files in {directory}")
        for path in files:
            with open(path) as fh:
                raw = yaml.safe_load(fh) or {}
            protocol = raw.get("protocol") or os.path.splitext(os.path.basename(path))[0]
            for entry in raw.get("controls") or []:
                cid = entry["id"]
                if cid in controls:
                    raise ValueError(f"Duplicate control id {cid} in {path}")
                controls[cid] = Control(
                    id=cid,
                    protocol=protocol,
                    title=entry.get("title", ""),
                    requirement=entry.get("requirement", ""),
                    baselines=list(entry.get("baselines") or []),
                    severity=Severity(entry.get("severity", "medium")),
                    remediation=entry.get("remediation", ""),
                    notes=entry.get("notes", ""),
                )
        return cls(controls)

    def get(self, check_id: str) -> Optional[Control]:
        return self._controls.get(check_id)

    def require(self, check_id: str) -> Control:
        ctrl = self._controls.get(check_id)
        if ctrl is None:
            raise KeyError(
                f"{check_id} has no catalog entry. Every check must trace to a "
                "named baseline; add it to the catalog before running it."
            )
        return ctrl

    def by_protocol(self, protocol: str) -> List[Control]:
        return [c for c in self._controls.values() if c.protocol == protocol]

    def protocols(self) -> List[str]:
        return sorted({c.protocol for c in self._controls.values()})

    def __len__(self) -> int:
        return len(self._controls)

    def __iter__(self):
        return iter(self._controls.values())
