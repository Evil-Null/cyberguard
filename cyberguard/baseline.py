"""Security baseline management."""
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyberguard.constants import BASELINES_DIR

_log = logging.getLogger("cyberguard")

class BaselineManager:
    """System baseline save/load/compare for File Integrity Monitoring."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    @staticmethod
    def hash_file(filepath: Path) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None

    def create_baseline(self, directories: List[str], name: str = "default") -> dict:
        baseline = {"name": name, "timestamp": datetime.now().isoformat(), "files": {}}
        for d in directories:
            p = Path(d)
            if not p.exists():
                continue
            try:
                for fp in p.rglob("*"):
                    if fp.is_file():
                        h = self.hash_file(fp)
                        if h:
                            st = fp.stat()
                            baseline["files"][str(fp)] = {
                                "hash": h,
                                "size": st.st_size,
                                "mtime": st.st_mtime,
                                "mode": oct(st.st_mode),
                            }
            except PermissionError:
                continue
        return baseline

    def save_baseline(self, baseline: dict, name: str = "default") -> Path:
        fp = BASELINES_DIR / f"{InputValidator.sanitize_filename(name)}.json"
        fp.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
        self.logger.info(f"Baseline saved: {fp}")
        return fp

    def load_baseline(self, name: str = "default") -> Optional[dict]:
        fp = BASELINES_DIR / f"{InputValidator.sanitize_filename(name)}.json"
        if fp.exists():
            try:
                return json.loads(fp.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return None
        return None

    def list_baselines(self) -> List[str]:
        return [f.stem for f in BASELINES_DIR.glob("*.json")]

    def compare_baseline(self, baseline: dict, current_dirs: List[str] = None) -> dict:
        current = {}
        dirs = current_dirs or list(set(str(Path(f).parent) for f in baseline.get("files", {})))
        for d in dirs:
            p = Path(d)
            if not p.exists():
                continue
            try:
                for fp in p.rglob("*"):
                    if fp.is_file():
                        h = self.hash_file(fp)
                        if h:
                            current[str(fp)] = h
            except PermissionError:
                continue

        old_files = baseline.get("files", {})
        added = [f for f in current if f not in old_files]
        removed = [f for f in old_files if f not in current]
        modified = [f for f in current if f in old_files and current[f] != old_files[f].get("hash")]

        return {
            "added": added[:100],
            "removed": removed[:100],
            "modified": modified[:100],
            "total_current": len(current),
            "total_baseline": len(old_files),
        }


# ═══════════════════════════════════════════════════════════════════════════
# ALERT MANAGER
# ═══════════════════════════════════════════════════════════════════════════
