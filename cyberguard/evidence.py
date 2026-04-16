"""Forensic evidence collection and management."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from cyberguard.commands import SystemCommandRunner

from cyberguard.constants import EVIDENCE_DIR, SENSITIVE_ENV_PREFIXES, VERSION

_log = logging.getLogger("cyberguard")

class EvidenceCollector:
    """Forensic evidence collection with chain of custody."""

    def __init__(self, cmd_runner: SystemCommandRunner, logger: logging.Logger):
        self.cmd = cmd_runner
        self.logger = logger

    def collect_files(self, file_paths: List[str], case_name: str,
                      examiner: str = "CyberGuard") -> dict:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        evidence_name = f"evidence_{InputValidator.sanitize_filename(case_name)}_{ts}"
        evidence_path = EVIDENCE_DIR / evidence_name
        evidence_path.mkdir(parents=True, exist_ok=True)

        manifest = {
            "case_name": case_name,
            "examiner": examiner,
            "timestamp": datetime.now().isoformat(),
            "tool": f"CyberGuard v{VERSION}",
            "files": [],
        }

        archive_path = evidence_path / f"{evidence_name}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            for fp_str in file_paths:
                fp = Path(fp_str)
                if not fp.exists():
                    manifest["files"].append({
                        "path": fp_str, "status": "NOT_FOUND",
                    })
                    continue
                try:
                    h = BaselineManager.hash_file(fp)
                    st = fp.stat()
                    tar.add(fp, arcname=fp.name)
                    manifest["files"].append({
                        "path": fp_str,
                        "name": fp.name,
                        "sha256": h,
                        "size": st.st_size,
                        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                        "mode": oct(st.st_mode),
                        "status": "COLLECTED",
                    })
                except (OSError, PermissionError) as e:
                    manifest["files"].append({
                        "path": fp_str, "status": "ERROR", "error": str(e),
                    })

        archive_hash = BaselineManager.hash_file(archive_path)
        manifest["archive"] = str(archive_path)
        manifest["archive_sha256"] = archive_hash

        manifest_path = evidence_path / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        coc_path = evidence_path / "chain_of_custody.txt"
        coc = f"""Chain of Custody Record
{'=' * 50}
Case: {case_name}
Evidence ID: {evidence_name}
Examiner: {examiner}
Collection Time: {manifest['timestamp']}
Tool: CyberGuard v{VERSION}
Archive: {archive_path}
Archive SHA-256: {archive_hash}
Files Collected: {sum(1 for f in manifest['files'] if f['status'] == 'COLLECTED')}
{'=' * 50}

Transfer Log:
1. {manifest['timestamp']} - Collected by {examiner} using CyberGuard
"""
        coc_path.write_text(coc, encoding="utf-8")

        self.logger.info(f"Evidence collected: {evidence_path}")
        return manifest

    def capture_volatile_data(self, case_name: str = "volatile") -> dict:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        data = {"timestamp": datetime.now().isoformat(), "case": case_name, "sections": {}}

        commands = {
            "date": ["date"],
            "uptime": ["uptime"],
            "whoami": ["whoami"],
            "who": ["who"],
            "w": ["w"],
            "uname": ["uname", "-a"],
            "hostname": ["hostname"],
            "processes": ["ps", "auxf"],
            "network_connections": ["ss", "-tunap"],
            "arp_cache": ["ip", "neigh", "show"],
            "routing_table": ["ip", "route", "show"],
            "dns_config": ["cat", "/etc/resolv.conf"],
            "mounted_fs": ["mount"],
            "loaded_modules": ["lsmod"],
            "open_files_count": ["bash", "-c", "lsof 2>/dev/null | wc -l"],
            "environment": ["env"],
            "crontab": ["crontab", "-l"],
            "iptables": ["iptables", "-L", "-n"],
        }

        for name, cmd in commands.items():
            rc, out, err = self.cmd.run(cmd, timeout=10)
            # Redact sensitive environment variables from forensic capture
            if name == "environment" and out:
                filtered_lines = []
                for line in out.splitlines():
                    var_name = line.split("=", 1)[0] if "=" in line else ""
                    if any(var_name.startswith(prefix) for prefix in SENSITIVE_ENV_PREFIXES):
                        filtered_lines.append(f"{var_name}=[REDACTED]")
                    else:
                        filtered_lines.append(line)
                out = "\n".join(filtered_lines)
            data["sections"][name] = {
                "command": " ".join(cmd),
                "output": out[:50000] if out else "",
                "error": err[:1000] if err else "",
                "return_code": rc,
            }

        return data


# ═══════════════════════════════════════════════════════════════════════════
# UI (Rich-based)
# ═══════════════════════════════════════════════════════════════════════════
