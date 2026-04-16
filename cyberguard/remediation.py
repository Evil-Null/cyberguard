"""Remediation tracking and management."""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from cyberguard.constants import REMEDIATION_FILE, Severity

_log = logging.getLogger("cyberguard")

class RemediationTracker:
    """Track findings: open → in-progress → resolved."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.items = self._load()

    def _load(self) -> List[dict]:
        if REMEDIATION_FILE.exists():
            try:
                return json.loads(REMEDIATION_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save(self):
        REMEDIATION_FILE.write_text(json.dumps(self.items, indent=2), encoding="utf-8")

    def add_finding(self, title: str, severity: str, description: str = "",
                    recommendation: str = "", due_date: str = "") -> dict:
        item = {
            "id": len(self.items) + 1,
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "status": "open",
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "due_date": due_date,
            "notes": [],
        }
        self.items.append(item)
        self._save()
        return item

    def update_status(self, item_id: int, status: str, note: str = ""):
        for item in self.items:
            if item["id"] == item_id:
                item["status"] = status
                item["updated"] = datetime.now().isoformat()
                if note:
                    item["notes"].append({
                        "timestamp": datetime.now().isoformat(),
                        "note": note,
                    })
                self._save()
                return True
        return False

    def get_open(self) -> List[dict]:
        return [i for i in self.items if i["status"] in ("open", "in-progress")]

    def get_all(self) -> List[dict]:
        return self.items

    def get_stats(self) -> dict:
        statuses = {}
        for item in self.items:
            s = item["status"]
            statuses[s] = statuses.get(s, 0) + 1
        return statuses

    def add_from_findings(self, findings: List[dict]):
        """Bulk add findings from assessment results."""
        for f in findings:
            if f.get("severity") in ("CRITICAL", "HIGH"):
                self.add_finding(
                    title=f.get("title", "Unknown finding"),
                    severity=f.get("severity", Severity.HIGH),
                    description=f.get("description", ""),
                    recommendation=f.get("recommendation", ""),
                )


# ═══════════════════════════════════════════════════════════════════════════
# EVIDENCE COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════
