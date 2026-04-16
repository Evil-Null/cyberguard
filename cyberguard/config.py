"""Configuration management and logging setup."""
import json
import logging
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Optional

from cyberguard.constants import (
    CONFIG_DIR, API_KEYS_FILE, CONFIG_FILE, HISTORY_FILE,
    BASELINES_DIR, EVIDENCE_DIR, LOGS_DIR, QUERIES_DIR, CACHE_DIR,
)

def setup_logging(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("cyberguard")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    return logger


class Config:
    """Manages configuration: API keys, directories, session, history."""

    def __init__(self):
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_dir = OUTPUT_DIR / f"session_{self.session_id}"
        self.log_file = LOGS_DIR / f"cyberguard_{self.session_id}.log"
        self.api_keys: Dict[str, str] = {}

        for d in [CONFIG_DIR, OUTPUT_DIR, CACHE_DIR, LOGS_DIR, BASELINES_DIR,
                  EVIDENCE_DIR, QUERIES_DIR, self.results_dir]:
            d.mkdir(parents=True, exist_ok=True)
            try:
                d.chmod(0o700)
            except OSError:
                pass

        self.logger = setup_logging(self.log_file)
        self._load_api_keys()
        self._load_config()

    def _load_api_keys(self):
        if API_KEYS_FILE.exists():
            try:
                data = json.loads(API_KEYS_FILE.read_text(encoding="utf-8"))
                self.api_keys = {k: v for k, v in data.items() if v}
            except (json.JSONDecodeError, OSError):
                self.api_keys = {}

    def _load_config(self):
        self.settings = {}
        if CONFIG_FILE.exists():
            try:
                self.settings = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

    def save_api_key(self, service: str, key: str):
        self.api_keys[service] = key.strip()
        API_KEYS_FILE.write_text(json.dumps(self.api_keys, indent=2), encoding="utf-8")
        try:
            API_KEYS_FILE.chmod(0o600)
        except OSError:
            pass

    def get_api_key(self, service: str) -> Optional[str]:
        return self.api_keys.get(service)

    def has_api_key(self, service: str) -> bool:
        return bool(self.api_keys.get(service))

    def save_settings(self):
        CONFIG_FILE.write_text(json.dumps(self.settings, indent=2), encoding="utf-8")

    def save_session_history(self, action: str, details: str):
        history = self.load_history()
        history.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "session": self.session_id,
            "action": action,
            "details": details,
        })
        history = history[-500:]
        try:
            HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")
        except OSError:
            pass

    def load_history(self, limit: int = 50) -> list:
        if HISTORY_FILE.exists():
            try:
                data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
                return data[-limit:] if limit else data
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def save_score(self, category: str, score: float, details: dict = None):
        scores = self._load_scores()
        scores.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "session": self.session_id,
            "category": category,
            "score": score,
            "details": details or {},
        })
        scores = scores[-1000:]
        try:
            SCORES_FILE.write_text(json.dumps(scores, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _load_scores(self) -> list:
        if SCORES_FILE.exists():
            try:
                return json.loads(SCORES_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def get_scores(self, category: str = None, limit: int = 20) -> list:
        scores = self._load_scores()
        if category:
            scores = [s for s in scores if s.get("category") == category]
        return scores[-limit:]


# ═══════════════════════════════════════════════════════════════════════════
# INPUT VALIDATOR
# ═══════════════════════════════════════════════════════════════════════════
