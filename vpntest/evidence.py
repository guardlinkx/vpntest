"""Evidence store: hashed, timestamped, and kept out of the report body.

A finding says what happened; the evidence proves it. Captures can contain
someone's traffic, so they are written to a run directory and referenced by
path and digest rather than inlined anywhere.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List


class EvidenceStore:
    def __init__(self, root: str, run_id: str = ""):
        self.run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.dir = os.path.join(root, self.run_id)
        os.makedirs(self.dir, exist_ok=True)
        self._index: List[Dict[str, Any]] = []

    def _record(self, relpath: str, kind: str, note: str) -> str:
        full = os.path.join(self.dir, relpath)
        with open(full, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        self._index.append({
            "path": relpath,
            "kind": kind,
            "note": note,
            "sha256": digest,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "size": os.path.getsize(full),
        })
        return relpath

    def text(self, check_id: str, name: str, body: str, note: str = "") -> str:
        safe = f"{check_id}_{name}".replace("/", "_").replace(" ", "_")
        relpath = f"{safe}.txt"
        with open(os.path.join(self.dir, relpath), "w") as fh:
            fh.write(body)
        return self._record(relpath, "text", note)

    def data(self, check_id: str, name: str, payload: Any, note: str = "") -> str:
        safe = f"{check_id}_{name}".replace("/", "_").replace(" ", "_")
        relpath = f"{safe}.json"
        with open(os.path.join(self.dir, relpath), "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
        return self._record(relpath, "json", note)

    def blob(self, check_id: str, name: str, payload: bytes, note: str = "") -> str:
        safe = f"{check_id}_{name}".replace("/", "_").replace(" ", "_")
        relpath = safe
        with open(os.path.join(self.dir, relpath), "wb") as fh:
            fh.write(payload)
        return self._record(relpath, "blob", note)

    def manifest(self) -> List[Dict[str, Any]]:
        return list(self._index)

    def write_manifest(self) -> str:
        path = os.path.join(self.dir, "MANIFEST.json")
        with open(path, "w") as fh:
            json.dump({
                "run_id": self.run_id,
                "written_at": datetime.now(timezone.utc).isoformat(),
                "files": self._index,
            }, fh, indent=2)
        return path
