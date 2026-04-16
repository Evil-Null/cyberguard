"""Input validation utilities."""
import ipaddress
import logging
import re
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

from cyberguard.constants import SSRF_BLOCKED_RANGES

_log = logging.getLogger("cyberguard")

class InputValidator:
    """Validates user inputs: IP, CIDR, domain, port, hash, CVE, PID."""

    IP_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )
    CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
    PORT_PATTERN = re.compile(r"^\d{1,5}$")
    DOMAIN_PATTERN = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    HASH_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
    HASH_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
    HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")

    @staticmethod
    def validate_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip.strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        try:
            ipaddress.ip_network(cidr.strip(), strict=False)
            return True
        except ValueError:
            return False

    @classmethod
    def validate_cve(cls, cve: str) -> bool:
        return bool(cls.CVE_PATTERN.match(cve.strip()))

    @classmethod
    def validate_port(cls, port: str) -> bool:
        port = port.strip()
        if cls.PORT_PATTERN.match(port):
            return 1 <= int(port) <= 65535
        return False

    @classmethod
    def validate_domain(cls, domain: str) -> bool:
        return bool(cls.DOMAIN_PATTERN.match(domain.strip()))

    @classmethod
    def validate_hash(cls, h: str) -> Optional[str]:
        h = h.strip()
        if cls.HASH_SHA256.match(h):
            return "sha256"
        if cls.HASH_SHA1.match(h):
            return "sha1"
        if cls.HASH_MD5.match(h):
            return "md5"
        return None

    @staticmethod
    def validate_pid(pid: str) -> bool:
        try:
            p = int(pid.strip())
            return p > 0
        except ValueError:
            return False

    @staticmethod
    def validate_email(email: str) -> bool:
        return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email.strip()))

    @staticmethod
    def validate_url(url: str) -> bool:
        try:
            r = urlparse(url.strip())
            return all([r.scheme in ("http", "https"), r.netloc])
        except Exception as e:
            _log.debug("URL parse failed: %s", e)
            return False

    @staticmethod
    def validate_port_range(port_range: str) -> Optional[Tuple[int, int]]:
        m = re.match(r"^(\d{1,5})-(\d{1,5})$", port_range.strip())
        if m:
            start, end = int(m.group(1)), int(m.group(2))
            if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                return (start, end)
        return None

    @classmethod
    def detect_input_type(cls, value: str) -> str:
        value = value.strip()
        if not value:
            return "unknown"
        if cls.validate_ip(value):
            return "ip"
        if value.startswith(("http://", "https://")):
            return "url"
        if cls.validate_domain(value):
            return "domain"
        return "unknown"

    @staticmethod
    def sanitize_filename(name: str) -> str:
        return re.sub(r'[^\w\-.]', '_', name.strip())[:100]


# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM COMMAND RUNNER
# ═══════════════════════════════════════════════════════════════════════════
