"""Alert management and notification."""
import json
import logging
import re
import smtplib
import socket
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyberguard.config import Config
from cyberguard.constants import ALERTS_FILE, CONFIG_DIR, Severity

_log = logging.getLogger("cyberguard")

class AlertManager:
    """Email and webhook alert notifications with encrypted credential storage."""

    _FERNET_KEY_FILE = CONFIG_DIR / ".alert_key"

    def __init__(self, config: Config):
        self.config = config
        self._fernet = self._get_or_create_fernet()
        self._load_config()

    def _get_or_create_fernet(self):
        """Get or create a machine-local Fernet key for encrypting SMTP credentials."""
        try:
            from cryptography.fernet import Fernet
            if self._FERNET_KEY_FILE.exists():
                key = self._FERNET_KEY_FILE.read_bytes().strip()
            else:
                key = Fernet.generate_key()
                self._FERNET_KEY_FILE.write_bytes(key)
                try:
                    self._FERNET_KEY_FILE.chmod(0o600)
                except OSError:
                    pass
            return Fernet(key)
        except Exception as e:
            self.config.logger.warning("Fernet key init failed: %s", e)
            return None

    def _encrypt_value(self, plaintext: str) -> str:
        if self._fernet and plaintext:
            return self._fernet.encrypt(plaintext.encode()).decode()
        return plaintext

    def _decrypt_value(self, ciphertext: str) -> str:
        if self._fernet and ciphertext:
            try:
                return self._fernet.decrypt(ciphertext.encode()).decode()
            except Exception as e:
                self.config.logger.debug("Decrypt failed, returning raw: %s", e)
                return ciphertext
        return ciphertext

    def _load_config(self):
        self.alerts_config = {}
        if ALERTS_FILE.exists():
            try:
                self.alerts_config = json.loads(ALERTS_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

    def save_config(self):
        ALERTS_FILE.write_text(json.dumps(self.alerts_config, indent=2), encoding="utf-8")
        try:
            ALERTS_FILE.chmod(0o600)
        except OSError:
            pass

    def configure_email(self, smtp_server: str, smtp_port: int, username: str,
                        password: str, from_addr: str, to_addr: str) -> None:
        self.alerts_config["email"] = {
            "smtp_server": smtp_server, "smtp_port": smtp_port,
            "username": username, "password": self._encrypt_value(password),
            "password_encrypted": self._fernet is not None,
            "from": from_addr, "to": to_addr, "enabled": True,
        }
        self.save_config()

    @staticmethod
    def validate_webhook_url(url: str) -> bool:
        """Validate webhook URL with SSRF protection against internal networks."""
        try:
            parsed = urlparse(url.strip())
            if parsed.scheme not in ("http", "https"):
                return False
            hostname = parsed.hostname
            if not hostname:
                return False
            resolved_ip = ipaddress.ip_address(socket.gethostbyname(hostname))
            for blocked in SSRF_BLOCKED_RANGES:
                if resolved_ip in blocked:
                    return False
            return True
        except (socket.gaierror, ValueError, OSError):
            return False

    def configure_webhook(self, url: str, name: str = "default") -> None:
        if not self.validate_webhook_url(url):
            self.config.logger.warning(f"Webhook URL blocked (SSRF protection): {url}")
            return
        webhooks = self.alerts_config.get("webhooks", {})
        webhooks[name] = {"url": url, "enabled": True}
        self.alerts_config["webhooks"] = webhooks
        self.save_config()

    def send_alert(self, subject: str, message: str, severity: str = Severity.INFO) -> None:
        self.config.logger.info(f"Alert [{severity}]: {subject}")
        email_cfg = self.alerts_config.get("email", {})
        if email_cfg.get("enabled"):
            self._send_email(subject, message, email_cfg)

        for name, wh in self.alerts_config.get("webhooks", {}).items():
            if wh.get("enabled"):
                self._send_webhook(subject, message, severity, wh["url"])

    def _send_email(self, subject: str, message: str, cfg: dict) -> None:
        try:
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(message)
            msg["Subject"] = f"[CyberGuard {VERSION}] {subject}"
            msg["From"] = cfg["from"]
            msg["To"] = cfg["to"]
            password = cfg.get("password", "")
            if cfg.get("password_encrypted"):
                password = self._decrypt_value(password)
            ssl_context = ssl.create_default_context()
            with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"], timeout=30) as s:
                s.starttls(context=ssl_context)
                s.login(cfg["username"], password)
                s.send_message(msg)
            self.config.logger.info(f"Email alert sent: {subject}")
        except Exception as e:
            self.config.logger.error(f"Email alert failed: {e}")

    def _send_webhook(self, subject: str, message: str, severity: str, url: str) -> None:
        try:
            if not self.validate_webhook_url(url):
                self.config.logger.warning(f"Webhook blocked (SSRF): {url}")
                return
            payload = {
                "text": f"**[{severity}] {subject}**\n{message}",
                "content": f"**[{severity}] {subject}**\n{message}",
                "username": f"CyberGuard v{VERSION}",
            }
            requests.post(url, json=payload, timeout=10)
            self.config.logger.info(f"Webhook alert sent: {subject}")
        except Exception as e:
            self.config.logger.error(f"Webhook alert failed: {e}")

    def is_configured(self) -> bool:
        if self.alerts_config.get("email", {}).get("enabled"):
            return True
        for wh in self.alerts_config.get("webhooks", {}).values():
            if wh.get("enabled"):
                return True
        return False


# ═══════════════════════════════════════════════════════════════════════════
# COMPLIANCE CHECKER
# ═══════════════════════════════════════════════════════════════════════════
