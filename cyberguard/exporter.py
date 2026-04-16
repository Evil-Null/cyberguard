"""Result export to multiple formats."""
import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from cyberguard.constants import Severity

_log = logging.getLogger("cyberguard")

class ResultExporter:
    """Exports results to JSON, CSV, TXT, HTML."""

    def __init__(self, results_dir: Path, logger: logging.Logger):
        self.results_dir = results_dir
        self.logger = logger

    def _filepath(self, name: str, ext: str) -> Path:
        safe_name = InputValidator.sanitize_filename(name)
        return self.results_dir / f"{safe_name}.{ext}"

    def export_json(self, data: Any, name: str) -> Path:
        fp = self._filepath(name, "json")
        fp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        self.logger.info(f"Exported JSON: {fp}")
        return fp

    def export_csv(self, rows: List[dict], name: str, fieldnames: List[str] = None) -> Path:
        if not rows:
            return self._filepath(name, "csv")
        fp = self._filepath(name, "csv")
        fields = fieldnames or list(rows[0].keys())
        with open(fp, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        self.logger.info(f"Exported CSV: {fp}")
        return fp

    def export_txt(self, content: str, name: str) -> Path:
        fp = self._filepath(name, "txt")
        fp.write_text(content, encoding="utf-8")
        self.logger.info(f"Exported TXT: {fp}")
        return fp

    def export_html(self, html_content: str, name: str) -> Path:
        fp = self._filepath(name, "html")
        fp.write_text(html_content, encoding="utf-8")
        self.logger.info(f"Exported HTML: {fp}")
        return fp

    def ask_export(self, data: Any, name: str, rows: List[dict] = None,
                   txt: str = None, html: str = None):
        """Interactive export prompt."""
        choices = ["JSON", "CSV", "TXT", "HTML", "Skip"]
        avail = ["JSON"]
        if rows:
            avail.append("CSV")
        if txt:
            avail.append("TXT")
        if html:
            avail.append("HTML")
        avail.append("Skip")

        choice = questionary.select("Export format:", choices=avail).ask()
        if not choice or choice == "Skip":
            return None
        if choice == "JSON":
            p = self.export_json(data, name)
        elif choice == "CSV" and rows:
            p = self.export_csv(rows, name)
        elif choice == "TXT" and txt:
            p = self.export_txt(txt, name)
        elif choice == "HTML" and html:
            p = self.export_html(html, name)
        else:
            return None
        console.print(f"  [green]Saved:[/green] {p}")
        return p


# ═══════════════════════════════════════════════════════════════════════════
# RISK SCORER
# ═══════════════════════════════════════════════════════════════════════════
