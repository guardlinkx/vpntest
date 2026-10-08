"""Machine-readable report. The HTML view is rendered from exactly this."""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..model import Finding


def build(findings: List[Finding], scope, catalog, evidence,
          summary: Dict[str, Any]) -> Dict[str, Any]:
    rows = []
    for f in findings:
        ctrl = catalog.get(f.check_id)
        rows.append({
            **f.to_dict(),
            "title": ctrl.title if ctrl else "",
            "requirement": ctrl.requirement if ctrl else "",
            "baselines": ctrl.baselines if ctrl else [],
        })
    return {
        "tool": "vpntest",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "scope": {
            "name": scope.name,
            "authorized_by": scope.authorized_by,
            "targets": [t.get("label", t["host"]) for t in scope.targets],
            "window": {
                "start": scope.window_start.isoformat() if scope.window_start else None,
                "end": scope.window_end.isoformat() if scope.window_end else None,
            },
            "allow_disruptive": scope.allow_disruptive,
        },
        "summary": summary,
        "findings": rows,
        "evidence": {
            "run_id": evidence.run_id,
            "directory": evidence.dir,
            "files": evidence.manifest(),
        },
    }


def write(report: Dict[str, Any], path: str) -> str:
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    return path
