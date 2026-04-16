#!/usr/bin/env python3
"""
CyberGuard Professional Security Toolkit v1.0
===============================================
A comprehensive cybersecurity toolkit for Linux systems.
Network scanning, system hardening, vulnerability assessment,
monitoring, threat intelligence, forensics, and compliance.

Requires: pip install rich questionary requests psutil dnspython cryptography
"""

import csv
import hashlib
import html as html_mod
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import time
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import questionary
    import requests
    from rich import box
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install rich questionary requests psutil dnspython cryptography")
    sys.exit(1)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import dns.resolver
    import dns.zone
    import dns.query
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

_log = logging.getLogger("cyberguard")


class Severity(StrEnum):
    """Standardized severity levels for findings and vulnerabilities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


VERSION = "1.0"
APP_NAME = "CyberGuard Professional Security Toolkit"
CONFIG_DIR = Path.home() / ".cyberguard"
API_KEYS_FILE = CONFIG_DIR / "api_keys.json"
CONFIG_FILE = CONFIG_DIR / "config.json"
ALERTS_FILE = CONFIG_DIR / "alerts.json"
IOCS_FILE = CONFIG_DIR / "iocs.json"
REMEDIATION_FILE = CONFIG_DIR / "remediation.json"
SCORES_FILE = CONFIG_DIR / "scores.json"
HISTORY_FILE = CONFIG_DIR / "history.json"
BASELINES_DIR = CONFIG_DIR / "baselines"
EVIDENCE_DIR = CONFIG_DIR / "evidence"
LOGS_DIR = CONFIG_DIR / "logs"
QUERIES_DIR = CONFIG_DIR / "queries"
CACHE_DIR = CONFIG_DIR / "cache"
OUTPUT_DIR = Path.home() / "cyberguard-results"
RATE_LIMIT_DELAY = 1.0
REQUEST_TIMEOUT = 30
MAX_RESULTS = 100
USER_AGENT = f"CyberGuard/{VERSION}"
MAX_BULK_IPS = 100
CACHE_TTL = 3600
MAX_LOG_LINES = 10000

# Sensitive environment variable prefixes to redact from forensic captures
SENSITIVE_ENV_PREFIXES = (
    "AWS_", "API_", "SECRET_", "TOKEN_", "PASSWORD_", "KEY_", "DATABASE_",
    "GITHUB_", "GITLAB_", "AZURE_", "GCP_", "SLACK_", "WEBHOOK_", "SMTP_",
    "PRIVATE_", "CREDENTIAL_", "AUTH_", "SESSION_", "COOKIE_",
)

# SSRF protection: blocked IP ranges for webhook validation
SSRF_BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 636, 993, 995, 1080, 1433, 1434, 1521, 1723, 2049,
    2082, 2083, 2086, 2087, 3306, 3389, 5060, 5432, 5900, 5901, 6379,
    6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 8000,
    8008, 8080, 8443, 8888, 9090, 9200, 9300, 10000, 27017, 28017,
    50000, 50070, 50075, 50090, 60010, 60030,
]

TOP_1000_PORTS = list(range(1, 1025)) + [
    1080, 1099, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2181, 2222,
    2375, 2376, 3000, 3128, 3306, 3389, 4443, 4444, 4848, 5000, 5060,
    5432, 5555, 5672, 5900, 5984, 6379, 6443, 6660, 6667, 7001, 7002,
    7077, 8000, 8008, 8009, 8020, 8042, 8080, 8081, 8088, 8443, 8787,
    8888, 9000, 9042, 9090, 9092, 9200, 9300, 9418, 9999, 10000, 11211,
    15672, 27017, 28017, 50000, 50070, 61616,
]

SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 6667, 1337, 31337, 12345, 54321, 9001, 9050,
    4445, 5554, 1234, 3127, 65535, 1338, 7777, 8787, 31338,
}

CRYPTO_MINERS = {
    "xmrig", "minerd", "cpuminer", "cgminer", "bfgminer", "ethminer",
    "claymore", "t-rex", "phoenixminer", "nbminer", "lolminer",
    "gminer", "trex", "ccminer", "nheqminer", "excavator",
}

UNNECESSARY_SERVICES = {
    "telnet", "rsh", "rlogin", "rexec", "tftp", "xinetd", "ypserv",
    "ypbind", "rpc.ypxfrd", "rpc.yppasswdd", "avahi-daemon", "cups",
    "isc-dhcp-server", "slapd", "nfs-kernel-server", "bind9", "vsftpd",
    "apache2", "nginx", "dovecot", "smbd", "squid", "snmpd",
}

KERNEL_SECURITY_PARAMS = {
    "net.ipv4.ip_forward": {"expected": "0", "desc": "IP forwarding disabled"},
    "net.ipv4.conf.all.send_redirects": {"expected": "0", "desc": "ICMP redirects disabled"},
    "net.ipv4.conf.default.send_redirects": {"expected": "0", "desc": "Default ICMP redirects disabled"},
    "net.ipv4.conf.all.accept_source_route": {"expected": "0", "desc": "Source routing disabled"},
    "net.ipv4.conf.default.accept_source_route": {"expected": "0", "desc": "Default source routing disabled"},
    "net.ipv4.conf.all.accept_redirects": {"expected": "0", "desc": "ICMP redirect acceptance disabled"},
    "net.ipv4.conf.default.accept_redirects": {"expected": "0", "desc": "Default ICMP redirect disabled"},
    "net.ipv4.conf.all.secure_redirects": {"expected": "0", "desc": "Secure ICMP redirects disabled"},
    "net.ipv4.conf.default.secure_redirects": {"expected": "0", "desc": "Default secure ICMP redirects disabled"},
    "net.ipv4.conf.all.log_martians": {"expected": "1", "desc": "Martian packet logging enabled"},
    "net.ipv4.conf.default.log_martians": {"expected": "1", "desc": "Default martian logging enabled"},
    "net.ipv4.icmp_echo_ignore_broadcasts": {"expected": "1", "desc": "Broadcast ICMP ignored"},
    "net.ipv4.icmp_ignore_bogus_error_responses": {"expected": "1", "desc": "Bogus ICMP responses ignored"},
    "net.ipv4.conf.all.rp_filter": {"expected": "1", "desc": "Reverse path filtering enabled"},
    "net.ipv4.conf.default.rp_filter": {"expected": "1", "desc": "Default reverse path filtering enabled"},
    "net.ipv4.tcp_syncookies": {"expected": "1", "desc": "TCP SYN cookies enabled"},
    "net.ipv6.conf.all.accept_ra": {"expected": "0", "desc": "IPv6 router advertisements disabled"},
    "net.ipv6.conf.default.accept_ra": {"expected": "0", "desc": "Default IPv6 RA disabled"},
    "kernel.randomize_va_space": {"expected": "2", "desc": "Full ASLR enabled"},
    "fs.suid_dumpable": {"expected": "0", "desc": "SUID core dumps disabled"},
    "kernel.core_uses_pid": {"expected": "1", "desc": "Core dump PID naming enabled"},
    "kernel.dmesg_restrict": {"expected": "1", "desc": "dmesg restricted to root"},
    "kernel.kptr_restrict": {"expected": "2", "desc": "Kernel pointer restriction enabled"},
    "kernel.yama.ptrace_scope": {"expected": "1", "desc": "Ptrace scope restricted"},
}

SSH_SECURITY_PARAMS = {
    "PermitRootLogin": {"expected": "no", "severity": Severity.HIGH},
    "PasswordAuthentication": {"expected": "no", "severity": Severity.HIGH},
    "PermitEmptyPasswords": {"expected": "no", "severity": Severity.HIGH},
    "X11Forwarding": {"expected": "no", "severity": Severity.MEDIUM},
    "MaxAuthTries": {"expected": "4", "severity": Severity.MEDIUM, "compare": "lte"},
    "Protocol": {"expected": "2", "severity": Severity.HIGH},
    "IgnoreRhosts": {"expected": "yes", "severity": Severity.MEDIUM},
    "HostbasedAuthentication": {"expected": "no", "severity": Severity.MEDIUM},
    "LoginGraceTime": {"expected": "60", "severity": Severity.LOW, "compare": "lte"},
    "ClientAliveInterval": {"expected": "300", "severity": Severity.LOW, "compare": "lte"},
    "ClientAliveCountMax": {"expected": "3", "severity": Severity.LOW, "compare": "lte"},
    "AllowAgentForwarding": {"expected": "no", "severity": Severity.LOW},
    "AllowTcpForwarding": {"expected": "no", "severity": Severity.LOW},
    "UsePAM": {"expected": "yes", "severity": Severity.MEDIUM},
}

MITRE_TECHNIQUES = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution, Persistence"},
    "T1053.003": {"name": "Cron", "tactic": "Execution, Persistence"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Persistence"},
    "T1078.003": {"name": "Local Accounts", "tactic": "Defense Evasion, Persistence"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1136": {"name": "Create Account", "tactic": "Persistence"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence"},
    "T1543.002": {"name": "Systemd Service", "tactic": "Persistence"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1552.001": {"name": "Credentials In Files", "tactic": "Credential Access"},
    "T1046": {"name": "Network Service Scanning", "tactic": "Discovery"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1485": {"name": "Data Destruction", "tactic": "Impact"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1070.002": {"name": "Clear Linux or Mac System Logs", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
}

CIS_CHECKS = [
    {"id": "1.1.1", "title": "Ensure mounting of cramfs is disabled", "cat": "Filesystem"},
    {"id": "1.1.2", "title": "Ensure mounting of squashfs is disabled", "cat": "Filesystem"},
    {"id": "1.1.3", "title": "Ensure mounting of udf is disabled", "cat": "Filesystem"},
    {"id": "1.3.1", "title": "Ensure AIDE is installed", "cat": "Filesystem Integrity"},
    {"id": "1.4.1", "title": "Ensure bootloader password is set", "cat": "Secure Boot"},
    {"id": "1.5.1", "title": "Ensure ASLR is enabled", "cat": "Process Hardening"},
    {"id": "1.5.3", "title": "Ensure prelink is not installed", "cat": "Process Hardening"},
    {"id": "2.1.1", "title": "Ensure time synchronization is in use", "cat": "Services"},
    {"id": "2.2.1", "title": "Ensure X Window System is not installed", "cat": "Services"},
    {"id": "2.2.2", "title": "Ensure Avahi Server is not installed", "cat": "Services"},
    {"id": "2.2.3", "title": "Ensure CUPS is not installed", "cat": "Services"},
    {"id": "2.2.4", "title": "Ensure DHCP Server is not installed", "cat": "Services"},
    {"id": "2.2.5", "title": "Ensure LDAP server is not installed", "cat": "Services"},
    {"id": "2.2.6", "title": "Ensure NFS is not installed", "cat": "Services"},
    {"id": "2.2.7", "title": "Ensure DNS Server is not installed", "cat": "Services"},
    {"id": "2.2.8", "title": "Ensure FTP Server is not installed", "cat": "Services"},
    {"id": "2.2.9", "title": "Ensure HTTP Server is not installed", "cat": "Services"},
    {"id": "2.2.10", "title": "Ensure IMAP/POP3 server is not installed", "cat": "Services"},
    {"id": "2.2.11", "title": "Ensure Samba is not installed", "cat": "Services"},
    {"id": "2.2.12", "title": "Ensure HTTP Proxy Server is not installed", "cat": "Services"},
    {"id": "2.2.13", "title": "Ensure SNMP Server is not installed", "cat": "Services"},
    {"id": "3.1.1", "title": "Ensure IP forwarding is disabled", "cat": "Network"},
    {"id": "3.1.2", "title": "Ensure packet redirect sending is disabled", "cat": "Network"},
    {"id": "3.2.1", "title": "Ensure source routed packets are not accepted", "cat": "Network"},
    {"id": "3.2.2", "title": "Ensure ICMP redirects are not accepted", "cat": "Network"},
    {"id": "3.2.3", "title": "Ensure secure ICMP redirects are not accepted", "cat": "Network"},
    {"id": "3.2.4", "title": "Ensure suspicious packets are logged", "cat": "Network"},
    {"id": "3.2.5", "title": "Ensure broadcast ICMP requests are ignored", "cat": "Network"},
    {"id": "3.2.6", "title": "Ensure bogus ICMP responses are ignored", "cat": "Network"},
    {"id": "3.2.7", "title": "Ensure Reverse Path Filtering is enabled", "cat": "Network"},
    {"id": "3.2.8", "title": "Ensure TCP SYN Cookies is enabled", "cat": "Network"},
    {"id": "3.3.1", "title": "Ensure IPv6 RA are not accepted", "cat": "Network"},
    {"id": "3.5.1", "title": "Ensure a firewall package is installed", "cat": "Firewall"},
    {"id": "3.5.2", "title": "Ensure firewall default deny policy", "cat": "Firewall"},
    {"id": "4.1.1", "title": "Ensure auditd is installed", "cat": "Logging"},
    {"id": "4.1.2", "title": "Ensure auditd service is enabled", "cat": "Logging"},
    {"id": "4.2.1", "title": "Ensure rsyslog is installed", "cat": "Logging"},
    {"id": "4.2.2", "title": "Ensure rsyslog service is enabled", "cat": "Logging"},
    {"id": "5.1.1", "title": "Ensure cron daemon is enabled", "cat": "Access"},
    {"id": "5.2.1", "title": "Ensure permissions on sshd_config", "cat": "SSH"},
    {"id": "5.2.4", "title": "Ensure SSH X11 forwarding is disabled", "cat": "SSH"},
    {"id": "5.2.5", "title": "Ensure SSH MaxAuthTries <= 4", "cat": "SSH"},
    {"id": "5.2.6", "title": "Ensure SSH IgnoreRhosts is enabled", "cat": "SSH"},
    {"id": "5.2.7", "title": "Ensure SSH HostbasedAuth is disabled", "cat": "SSH"},
    {"id": "5.2.8", "title": "Ensure SSH root login is disabled", "cat": "SSH"},
    {"id": "5.2.9", "title": "Ensure SSH PermitEmptyPasswords is disabled", "cat": "SSH"},
    {"id": "5.3.1", "title": "Ensure password creation requirements", "cat": "Authentication"},
    {"id": "5.4.1", "title": "Ensure password expiration <= 365 days", "cat": "Authentication"},
    {"id": "6.1.1", "title": "Ensure permissions on /etc/passwd", "cat": "File Permissions"},
    {"id": "6.1.2", "title": "Ensure permissions on /etc/shadow", "cat": "File Permissions"},
    {"id": "6.1.3", "title": "Ensure permissions on /etc/group", "cat": "File Permissions"},
    {"id": "6.1.4", "title": "Ensure no world-writable files", "cat": "File Permissions"},
    {"id": "6.2.1", "title": "Ensure no duplicate UIDs", "cat": "User Settings"},
    {"id": "6.2.3", "title": "Ensure root is only UID 0 account", "cat": "User Settings"},
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

console = Console()


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════════

def setup_logging(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("cyberguard")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    return logger


# ═══════════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════

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

class SystemCommandRunner:
    """Safe subprocess wrapper with timeout, sanitization, logging."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def run(self, cmd: List[str], timeout: int = 60, capture: bool = True,
            check: bool = False) -> Tuple[int, str, str]:
        """Run a command safely. Returns (returncode, stdout, stderr)."""
        self.logger.debug(f"Running command: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            if result.returncode != 0:
                self.logger.debug(f"Command returned {result.returncode}: {stderr[:200]}")
            return result.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            return -1, "", f"Command timed out after {timeout}s"
        except FileNotFoundError:
            self.logger.debug(f"Command not found: {cmd[0]}")
            return -2, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            self.logger.error(f"Command failed: {e}")
            return -3, "", str(e)

    def run_sudo(self, cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
        """Run command with sudo prefix."""
        return self.run(["sudo", "-n"] + cmd, timeout=timeout)

    def has_command(self, name: str) -> bool:
        return shutil.which(name) is not None

    def has_sudo(self) -> bool:
        rc, _, _ = self.run(["sudo", "-n", "true"], timeout=5)
        return rc == 0

    def read_proc_file(self, path: str) -> Optional[str]:
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return None

    def read_sysctl(self, param: str) -> Optional[str]:
        rc, out, _ = self.run(["sysctl", "-n", param], timeout=5)
        if rc == 0:
            return out.strip()
        return None


# ═══════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE API
# ═══════════════════════════════════════════════════════════════════════════

class ThreatIntelAPI:
    """VirusTotal, AbuseIPDB, NVD API with rate-limiting and caching."""

    def __init__(self, config: Config):
        self.config = config
        self._last_request: Dict[str, float] = {}
        self._cache: Dict[str, Tuple[float, Any]] = {}

    def _rate_limit(self, service: str, delay: float = 1.0):
        last = self._last_request.get(service, 0)
        elapsed = time.time() - last
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request[service] = time.time()

    def _get_cached(self, key: str) -> Optional[Any]:
        if key in self._cache:
            ts, data = self._cache[key]
            if time.time() - ts < CACHE_TTL:
                return data
            del self._cache[key]
        return None

    def _set_cache(self, key: str, data: Any):
        self._cache[key] = (time.time(), data)

    # ── VirusTotal ──

    def vt_ip_reputation(self, ip: str) -> dict:
        key = self.config.get_api_key("virustotal")
        if not key:
            raise ValueError("VirusTotal API key not configured")
        cache_key = f"vt_ip_{ip}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        self._rate_limit("virustotal", 15.0)
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key, "User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        self._set_cache(cache_key, data)
        return data

    def vt_hash_reputation(self, file_hash: str) -> dict:
        key = self.config.get_api_key("virustotal")
        if not key:
            raise ValueError("VirusTotal API key not configured")
        cache_key = f"vt_hash_{file_hash}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        self._rate_limit("virustotal", 15.0)
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": key, "User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        self._set_cache(cache_key, data)
        return data

    def vt_url_scan(self, url: str) -> dict:
        key = self.config.get_api_key("virustotal")
        if not key:
            raise ValueError("VirusTotal API key not configured")
        self._rate_limit("virustotal", 15.0)
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": key, "User-Agent": USER_AGENT},
            data={"url": url},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    # ── AbuseIPDB ──

    def abuseipdb_check(self, ip: str, max_age_days: int = 90) -> dict:
        key = self.config.get_api_key("abuseipdb")
        if not key:
            raise ValueError("AbuseIPDB API key not configured")
        cache_key = f"abuse_{ip}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        self._rate_limit("abuseipdb", 1.0)
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        self._set_cache(cache_key, data)
        return data

    # ── NVD (National Vulnerability Database) ──

    def nvd_cve_lookup(self, cve_id: str) -> dict:
        cache_key = f"nvd_{cve_id}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        self._rate_limit("nvd", 0.6)
        headers = {"User-Agent": USER_AGENT}
        nvd_key = self.config.get_api_key("nvd")
        if nvd_key:
            headers["apiKey"] = nvd_key
        resp = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        self._set_cache(cache_key, data)
        return data

    def nvd_search(self, keyword: str, results_per_page: int = 20) -> dict:
        self._rate_limit("nvd", 0.6)
        headers = {"User-Agent": USER_AGENT}
        nvd_key = self.config.get_api_key("nvd")
        if nvd_key:
            headers["apiKey"] = nvd_key
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": results_per_page},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()


# ═══════════════════════════════════════════════════════════════════════════
# RESULT EXPORTER
# ═══════════════════════════════════════════════════════════════════════════

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

class RiskScorer:
    """Security risk scoring 0-100 for hosts, networks, compliance."""

    @staticmethod
    def score_host(findings: List[dict]) -> dict:
        score = 100.0
        deductions = []
        for f in findings:
            sev = f.get("severity", Severity.LOW)
            if sev == Severity.CRITICAL:
                d = 25.0
            elif sev == Severity.HIGH:
                d = 15.0
            elif sev == Severity.MEDIUM:
                d = 8.0
            else:
                d = 3.0
            score -= d
            deductions.append({"finding": f.get("title", "Unknown"), "deduction": d})
        score = max(0.0, score)
        grade = RiskScorer._grade(score)
        return {"score": round(score, 1), "grade": grade, "deductions": deductions}

    @staticmethod
    def score_compliance(passed: int, total: int) -> dict:
        if total == 0:
            return {"score": 0, "grade": "N/A", "passed": 0, "total": 0}
        score = (passed / total) * 100
        grade = RiskScorer._grade(score)
        return {"score": round(score, 1), "grade": grade, "passed": passed, "total": total}

    @staticmethod
    def score_network(open_ports: int, suspicious_ports: int, vulns: int) -> dict:
        score = 100.0
        score -= min(open_ports * 2, 30)
        score -= suspicious_ports * 15
        score -= min(vulns * 10, 40)
        score = max(0.0, score)
        return {"score": round(score, 1), "grade": RiskScorer._grade(score)}

    @staticmethod
    def _grade(score: float) -> str:
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    @staticmethod
    def aggregate(scores: List[dict]) -> dict:
        if not scores:
            return {"score": 0, "grade": "N/A"}
        avg = sum(s.get("score", 0) for s in scores) / len(scores)
        return {"score": round(avg, 1), "grade": RiskScorer._grade(avg)}


# ═══════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════

class HTMLReportGenerator:
    """Generates standalone HTML reports with dark theme and inline CSS."""

    STYLE = """
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
               background: #1a1a2e; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00d4ff; text-align: center; margin: 20px 0; font-size: 28px; }
        h2 { color: #00d4ff; border-bottom: 2px solid #16213e; padding-bottom: 8px;
             margin: 25px 0 15px; font-size: 20px; }
        h3 { color: #e94560; margin: 15px 0 10px; font-size: 16px; }
        .header { background: #16213e; border-radius: 10px; padding: 20px;
                  margin-bottom: 20px; text-align: center; }
        .header .subtitle { color: #888; font-size: 14px; margin-top: 5px; }
        .card { background: #16213e; border-radius: 8px; padding: 15px;
                margin-bottom: 15px; border-left: 4px solid #00d4ff; }
        .card.critical { border-left-color: #ff0040; }
        .card.high { border-left-color: #ff6b35; }
        .card.medium { border-left-color: #ffc107; }
        .card.low { border-left-color: #28a745; }
        .card.pass { border-left-color: #28a745; }
        .card.fail { border-left-color: #ff0040; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { background: #0f3460; color: #00d4ff; padding: 10px; text-align: left;
             font-size: 13px; }
        td { padding: 8px 10px; border-bottom: 1px solid #1a1a3e; font-size: 13px; }
        tr:hover { background: #1a1a3e; }
        .score-box { display: inline-block; padding: 15px 25px; border-radius: 10px;
                     font-size: 36px; font-weight: bold; text-align: center;
                     margin: 10px; }
        .score-a { background: #28a745; color: white; }
        .score-b { background: #5cb85c; color: white; }
        .score-c { background: #ffc107; color: #333; }
        .score-d { background: #ff6b35; color: white; }
        .score-f { background: #ff0040; color: white; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
                 font-size: 11px; font-weight: bold; }
        .badge-critical { background: #ff0040; color: white; }
        .badge-high { background: #ff6b35; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; color: white; }
        .badge-pass { background: #28a745; color: white; }
        .badge-fail { background: #ff0040; color: white; }
        .badge-info { background: #00d4ff; color: #333; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 15px; margin: 15px 0; }
        .summary-item { background: #0f3460; border-radius: 8px; padding: 15px;
                        text-align: center; }
        .summary-item .value { font-size: 28px; font-weight: bold; color: #00d4ff; }
        .summary-item .label { font-size: 12px; color: #888; margin-top: 5px; }
        .footer { text-align: center; color: #555; margin-top: 30px; padding: 15px;
                  border-top: 1px solid #16213e; font-size: 12px; }
        .progress-bar { background: #0f3460; border-radius: 5px; height: 20px;
                        overflow: hidden; margin: 5px 0; }
        .progress-fill { height: 100%; border-radius: 5px; transition: width 0.3s; }
        .recommendation { background: #0f3460; border-radius: 6px; padding: 12px;
                          margin: 8px 0; border-left: 3px solid #ffc107; }
    </style>"""

    @classmethod
    def _esc(cls, value: Any) -> str:
        """Escape user-controlled strings to prevent XSS in HTML reports."""
        return html_mod.escape(str(value)) if value else ""

    @classmethod
    def _wrap(cls, title: str, body: str) -> str:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        safe_title = cls._esc(title)
        return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
<title>{safe_title} - CyberGuard</title>{cls.STYLE}</head>
<body><div class="container">
<div class="header"><h1>🛡️ {safe_title}</h1>
<div class="subtitle">Generated by CyberGuard Professional Security Toolkit v{VERSION} | {ts}</div></div>
{body}
<div class="footer">CyberGuard Professional Security Toolkit v{VERSION} | Report generated {ts}</div>
</div></body></html>"""

    @classmethod
    def _severity_badge(cls, severity: str) -> str:
        s = severity.lower()
        return f'<span class="badge badge-{s}">{severity}</span>'

    @classmethod
    def _score_box(cls, score: float, grade: str) -> str:
        g = grade.lower()
        return f'<div class="score-box score-{g}">{score}/100<br><small>Grade {grade}</small></div>'

    @classmethod
    def _progress_bar(cls, pct: float, color: str = "#00d4ff") -> str:
        return f'<div class="progress-bar"><div class="progress-fill" style="width:{pct}%;background:{color}"></div></div>'

    @classmethod
    def assessment_report(cls, findings: List[dict], scores: dict,
                          title: str = "Security Assessment Report") -> str:
        body = ""
        # Score overview
        body += '<h2>Score Overview</h2><div class="summary-grid">'
        for cat, sc in scores.items():
            body += f'<div class="summary-item"><div class="value">{sc.get("score", 0)}</div>'
            body += f'<div class="label">{cls._esc(cat)} (Grade {cls._esc(sc.get("grade", "N/A"))})</div></div>'
        body += '</div>'

        # Findings
        if findings:
            body += '<h2>Findings</h2>'
            for f in findings:
                sev = f.get("severity", Severity.LOW).lower()
                body += f'<div class="card {html_mod.escape(sev)}">'
                body += f'<h3>{cls._severity_badge(f.get("severity", Severity.LOW))} {cls._esc(f.get("title", ""))}</h3>'
                body += f'<p>{cls._esc(f.get("description", ""))}</p>'
                if f.get("recommendation"):
                    body += f'<div class="recommendation"><strong>Recommendation:</strong> {cls._esc(f["recommendation"])}</div>'
                body += '</div>'

        return cls._wrap(title, body)

    @classmethod
    def compliance_report(cls, results: List[dict], framework: str,
                          score: dict) -> str:
        body = f'<h2>{framework} Compliance</h2>'
        body += cls._score_box(score.get("score", 0), score.get("grade", "N/A"))
        body += f'<p>Passed: {score.get("passed", 0)} / {score.get("total", 0)}</p>'
        body += cls._progress_bar(score.get("score", 0))

        body += '<table><tr><th>ID</th><th>Check</th><th>Status</th><th>Details</th></tr>'
        for r in results:
            status = r.get("status", "FAIL")
            badge = '<span class="badge badge-pass">PASS</span>' if status == "PASS" else '<span class="badge badge-fail">FAIL</span>'
            body += f'<tr><td>{cls._esc(r.get("id", ""))}</td><td>{cls._esc(r.get("title", ""))}</td>'
            body += f'<td>{badge}</td><td>{cls._esc(r.get("details", ""))}</td></tr>'
        body += '</table>'
        return cls._wrap(f"{framework} Compliance Report", body)

    @classmethod
    def hardening_report(cls, categories: Dict[str, List[dict]], overall_score: dict) -> str:
        body = '<h2>Overall Security Score</h2>'
        body += cls._score_box(overall_score.get("score", 0), overall_score.get("grade", "N/A"))

        for cat_name, checks in categories.items():
            passed = sum(1 for c in checks if c.get("status") == "PASS")
            total = len(checks)
            pct = (passed / total * 100) if total else 0
            body += f'<h2>{cls._esc(cat_name)}</h2>'
            body += f'<p>Passed: {passed}/{total} ({pct:.0f}%)</p>'
            body += cls._progress_bar(pct, "#28a745" if pct >= 80 else "#ffc107" if pct >= 60 else "#ff0040")
            body += '<table><tr><th>Check</th><th>Status</th><th>Details</th></tr>'
            for c in checks:
                st = c.get("status", "FAIL")
                badge = '<span class="badge badge-pass">PASS</span>' if st == "PASS" else '<span class="badge badge-fail">FAIL</span>'
                body += f'<tr><td>{cls._esc(c.get("title", ""))}</td><td>{badge}</td><td>{cls._esc(c.get("details", ""))}</td></tr>'
            body += '</table>'

        return cls._wrap("System Hardening Report", body)

    @classmethod
    def vulnerability_report(cls, vulns: List[dict], score: dict) -> str:
        body = '<h2>Vulnerability Summary</h2>'
        body += cls._score_box(score.get("score", 0), score.get("grade", "N/A"))

        counts = {}
        for v in vulns:
            s = v.get("severity", Severity.LOW)
            counts[s] = counts.get(s, 0) + 1
        body += '<div class="summary-grid">'
        for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            body += f'<div class="summary-item"><div class="value">{counts.get(s, 0)}</div>'
            body += f'<div class="label">{s}</div></div>'
        body += '</div>'

        if vulns:
            body += '<h2>Vulnerability Details</h2>'
            body += '<table><tr><th>ID</th><th>Severity</th><th>Description</th><th>Affected</th></tr>'
            for v in vulns:
                body += f'<tr><td>{cls._esc(v.get("id", "N/A"))}</td>'
                body += f'<td>{cls._severity_badge(v.get("severity", Severity.LOW))}</td>'
                body += f'<td>{cls._esc(v.get("description", ""))}</td>'
                body += f'<td>{cls._esc(v.get("affected", ""))}</td></tr>'
            body += '</table>'

        return cls._wrap("Vulnerability Assessment Report", body)

    @classmethod
    def executive_summary(cls, grade: str, score: float, findings_count: int,
                          top_findings: List[dict], recommendations: List[str]) -> str:
        body = '<h2>Security Grade</h2>'
        body += f'<div style="text-align:center">{cls._score_box(score, grade)}</div>'
        body += f'<div class="summary-grid">'
        body += f'<div class="summary-item"><div class="value">{findings_count}</div><div class="label">Total Findings</div></div>'

        crit = sum(1 for f in top_findings if f.get("severity") == Severity.CRITICAL)
        high = sum(1 for f in top_findings if f.get("severity") == Severity.HIGH)
        body += f'<div class="summary-item"><div class="value">{crit}</div><div class="label">Critical</div></div>'
        body += f'<div class="summary-item"><div class="value">{high}</div><div class="label">High</div></div>'
        body += '</div>'

        if top_findings:
            body += '<h2>Top Findings</h2>'
            for f in top_findings[:10]:
                sev = f.get("severity", Severity.LOW).lower()
                body += f'<div class="card {html_mod.escape(sev)}">'
                body += f'{cls._severity_badge(f.get("severity", Severity.LOW))} <strong>{cls._esc(f.get("title", ""))}</strong>'
                body += f'<p>{cls._esc(f.get("description", ""))}</p></div>'

        if recommendations:
            body += '<h2>Key Recommendations</h2>'
            for i, r in enumerate(recommendations[:10], 1):
                body += f'<div class="recommendation">{i}. {cls._esc(r)}</div>'

        return cls._wrap("Executive Security Summary", body)


# ═══════════════════════════════════════════════════════════════════════════
# BASELINE MANAGER
# ═══════════════════════════════════════════════════════════════════════════

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

class ComplianceChecker:
    """NIST CSF and CIS Benchmark compliance checking."""

    def __init__(self, cmd_runner: SystemCommandRunner, logger: logging.Logger):
        self.cmd = cmd_runner
        self.logger = logger

    def run_cis_checks(self) -> List[dict]:
        results = []
        for check in CIS_CHECKS:
            cid = check["id"]
            result = {"id": cid, "title": check["title"], "category": check["cat"],
                      "status": "FAIL", "details": ""}
            try:
                if cid == "1.1.1":
                    result = self._check_module_disabled("cramfs", result)
                elif cid == "1.1.2":
                    result = self._check_module_disabled("squashfs", result)
                elif cid == "1.1.3":
                    result = self._check_module_disabled("udf", result)
                elif cid == "1.3.1":
                    result = self._check_package_installed("aide", result)
                elif cid == "1.4.1":
                    result = self._check_grub_password(result)
                elif cid == "1.5.1":
                    result = self._check_aslr(result)
                elif cid == "1.5.3":
                    result = self._check_package_not_installed("prelink", result)
                elif cid == "2.1.1":
                    result = self._check_time_sync(result)
                elif cid.startswith("2.2."):
                    svc_map = {
                        "2.2.1": "xserver-xorg", "2.2.2": "avahi-daemon",
                        "2.2.3": "cups", "2.2.4": "isc-dhcp-server",
                        "2.2.5": "slapd", "2.2.6": "nfs-kernel-server",
                        "2.2.7": "bind9", "2.2.8": "vsftpd",
                        "2.2.9": "apache2", "2.2.10": "dovecot-imapd",
                        "2.2.11": "samba", "2.2.12": "squid",
                        "2.2.13": "snmpd",
                    }
                    pkg = svc_map.get(cid, "")
                    if pkg:
                        result = self._check_package_not_installed(pkg, result)
                elif cid.startswith("3.1.") or cid.startswith("3.2.") or cid.startswith("3.3."):
                    result = self._check_sysctl_param(cid, result)
                elif cid == "3.5.1":
                    result = self._check_firewall_installed(result)
                elif cid == "3.5.2":
                    result = self._check_firewall_default_deny(result)
                elif cid == "4.1.1":
                    result = self._check_package_installed("auditd", result)
                elif cid == "4.1.2":
                    result = self._check_service_enabled("auditd", result)
                elif cid == "4.2.1":
                    result = self._check_package_installed("rsyslog", result)
                elif cid == "4.2.2":
                    result = self._check_service_enabled("rsyslog", result)
                elif cid == "5.1.1":
                    result = self._check_service_enabled("cron", result)
                elif cid == "5.2.1":
                    result = self._check_file_perms("/etc/ssh/sshd_config", 0o600, result)
                elif cid.startswith("5.2."):
                    result = self._check_ssh_param(cid, result)
                elif cid == "5.3.1":
                    result = self._check_password_quality(result)
                elif cid == "5.4.1":
                    result = self._check_password_expiry(result)
                elif cid == "6.1.1":
                    result = self._check_file_perms("/etc/passwd", 0o644, result)
                elif cid == "6.1.2":
                    result = self._check_file_perms("/etc/shadow", 0o640, result)
                elif cid == "6.1.3":
                    result = self._check_file_perms("/etc/group", 0o644, result)
                elif cid == "6.1.4":
                    result = self._check_world_writable(result)
                elif cid == "6.2.1":
                    result = self._check_duplicate_uids(result)
                elif cid == "6.2.3":
                    result = self._check_root_only_uid0(result)
            except Exception as e:
                result["details"] = f"Check error: {e}"
            results.append(result)
        return results

    def _check_module_disabled(self, module: str, result: dict) -> dict:
        rc, out, _ = self.cmd.run(["modprobe", "-n", "-v", module], timeout=5)
        if "install /bin/true" in out or "install /bin/false" in out:
            result["status"] = "PASS"
            result["details"] = f"{module} module is disabled"
        else:
            result["details"] = f"{module} module may be loadable"
        return result

    def _check_package_installed(self, pkg: str, result: dict) -> dict:
        rc, out, _ = self.cmd.run(["dpkg", "-s", pkg], timeout=5)
        if rc == 0 and "Status: install ok installed" in out:
            result["status"] = "PASS"
            result["details"] = f"{pkg} is installed"
        else:
            result["details"] = f"{pkg} is not installed"
        return result

    def _check_package_not_installed(self, pkg: str, result: dict) -> dict:
        rc, out, _ = self.cmd.run(["dpkg", "-s", pkg], timeout=5)
        if rc != 0 or "is not installed" in out:
            result["status"] = "PASS"
            result["details"] = f"{pkg} is not installed"
        else:
            result["details"] = f"{pkg} is installed (should be removed)"
        return result

    def _check_grub_password(self, result: dict) -> dict:
        grub_cfg = Path("/boot/grub/grub.cfg")
        if grub_cfg.exists():
            try:
                content = grub_cfg.read_text(errors="replace")
                if "password" in content.lower():
                    result["status"] = "PASS"
                    result["details"] = "Bootloader password appears set"
                else:
                    result["details"] = "No bootloader password detected"
            except PermissionError:
                result["details"] = "Cannot read grub.cfg (permission denied)"
        else:
            result["details"] = "grub.cfg not found"
        return result

    def _check_aslr(self, result: dict) -> dict:
        val = self.cmd.read_sysctl("kernel.randomize_va_space")
        if val == "2":
            result["status"] = "PASS"
            result["details"] = "Full ASLR enabled (value=2)"
        else:
            result["details"] = f"ASLR value={val} (expected 2)"
        return result

    def _check_time_sync(self, result: dict) -> dict:
        for svc in ["chronyd", "systemd-timesyncd", "ntpd"]:
            rc, out, _ = self.cmd.run(["systemctl", "is-active", svc], timeout=5)
            if rc == 0 and "active" in out:
                result["status"] = "PASS"
                result["details"] = f"Time sync via {svc}"
                return result
        result["details"] = "No time synchronization service active"
        return result

    def _check_sysctl_param(self, cid: str, result: dict) -> dict:
        sysctl_map = {
            "3.1.1": "net.ipv4.ip_forward",
            "3.1.2": "net.ipv4.conf.all.send_redirects",
            "3.2.1": "net.ipv4.conf.all.accept_source_route",
            "3.2.2": "net.ipv4.conf.all.accept_redirects",
            "3.2.3": "net.ipv4.conf.all.secure_redirects",
            "3.2.4": "net.ipv4.conf.all.log_martians",
            "3.2.5": "net.ipv4.icmp_echo_ignore_broadcasts",
            "3.2.6": "net.ipv4.icmp_ignore_bogus_error_responses",
            "3.2.7": "net.ipv4.conf.all.rp_filter",
            "3.2.8": "net.ipv4.tcp_syncookies",
            "3.3.1": "net.ipv6.conf.all.accept_ra",
        }
        param = sysctl_map.get(cid)
        if not param:
            return result
        expected = KERNEL_SECURITY_PARAMS.get(param, {}).get("expected", "0")
        val = self.cmd.read_sysctl(param)
        if val == expected:
            result["status"] = "PASS"
            result["details"] = f"{param} = {val}"
        else:
            result["details"] = f"{param} = {val} (expected {expected})"
        return result

    def _check_firewall_installed(self, result: dict) -> dict:
        for pkg in ["ufw", "iptables", "nftables", "firewalld"]:
            rc, _, _ = self.cmd.run(["dpkg", "-s", pkg], timeout=5)
            if rc == 0:
                result["status"] = "PASS"
                result["details"] = f"Firewall package: {pkg}"
                return result
        result["details"] = "No firewall package installed"
        return result

    def _check_firewall_default_deny(self, result: dict) -> dict:
        rc, out, _ = self.cmd.run(["ufw", "status", "verbose"], timeout=5)
        if rc == 0 and "deny (incoming)" in out.lower():
            result["status"] = "PASS"
            result["details"] = "Default incoming policy is deny"
        else:
            result["details"] = "Default deny not confirmed"
        return result

    def _check_service_enabled(self, svc: str, result: dict) -> dict:
        rc, out, _ = self.cmd.run(["systemctl", "is-enabled", svc], timeout=5)
        if rc == 0 and "enabled" in out:
            result["status"] = "PASS"
            result["details"] = f"{svc} is enabled"
        else:
            result["details"] = f"{svc} is not enabled"
        return result

    def _check_file_perms(self, path: str, expected_mode: int, result: dict) -> dict:
        p = Path(path)
        if not p.exists():
            result["details"] = f"{path} not found"
            return result
        mode = p.stat().st_mode & 0o777
        if mode <= expected_mode:
            result["status"] = "PASS"
            result["details"] = f"{path} permissions: {oct(mode)}"
        else:
            result["details"] = f"{path} permissions: {oct(mode)} (expected <= {oct(expected_mode)})"
        return result

    def _check_ssh_param(self, cid: str, result: dict) -> dict:
        ssh_map = {
            "5.2.4": ("X11Forwarding", "no"),
            "5.2.5": ("MaxAuthTries", "4"),
            "5.2.6": ("IgnoreRhosts", "yes"),
            "5.2.7": ("HostbasedAuthentication", "no"),
            "5.2.8": ("PermitRootLogin", "no"),
            "5.2.9": ("PermitEmptyPasswords", "no"),
        }
        param, expected = ssh_map.get(cid, ("", ""))
        if not param:
            return result
        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            result["details"] = "sshd_config not found"
            return result
        try:
            content = sshd_config.read_text(errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0].lower() == param.lower():
                    val = parts[1]
                    if cid == "5.2.5":
                        if int(val) <= int(expected):
                            result["status"] = "PASS"
                    elif val.lower() == expected.lower():
                        result["status"] = "PASS"
                    result["details"] = f"{param} = {val}"
                    return result
            result["details"] = f"{param} not explicitly set"
        except (OSError, PermissionError):
            result["details"] = "Cannot read sshd_config"
        return result

    def _check_password_quality(self, result: dict) -> dict:
        pam_file = Path("/etc/pam.d/common-password")
        if pam_file.exists():
            try:
                content = pam_file.read_text(errors="replace")
                if "pam_pwquality" in content or "pam_cracklib" in content:
                    result["status"] = "PASS"
                    result["details"] = "Password quality module configured"
                else:
                    result["details"] = "No password quality module found"
            except (OSError, PermissionError):
                result["details"] = "Cannot read PAM config"
        else:
            result["details"] = "PAM password config not found"
        return result

    def _check_password_expiry(self, result: dict) -> dict:
        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            try:
                content = login_defs.read_text(errors="replace")
                for line in content.splitlines():
                    if line.strip().startswith("PASS_MAX_DAYS"):
                        val = line.split()[-1]
                        try:
                            if int(val) <= 365:
                                result["status"] = "PASS"
                                result["details"] = f"PASS_MAX_DAYS = {val}"
                            else:
                                result["details"] = f"PASS_MAX_DAYS = {val} (should be <= 365)"
                        except ValueError:
                            result["details"] = f"Cannot parse PASS_MAX_DAYS: {val}"
                        return result
                result["details"] = "PASS_MAX_DAYS not set"
            except (OSError, PermissionError):
                result["details"] = "Cannot read login.defs"
        else:
            result["details"] = "login.defs not found"
        return result

    def _check_world_writable(self, result: dict) -> dict:
        rc, out, _ = self.cmd.run(
            ["find", "/", "-maxdepth", "3", "-xdev", "-type", "f", "-perm", "-0002",
             "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
            timeout=30
        )
        files = [f for f in out.strip().splitlines() if f]
        if not files:
            result["status"] = "PASS"
            result["details"] = "No world-writable files found"
        else:
            result["details"] = f"Found {len(files)} world-writable file(s)"
        return result

    def _check_duplicate_uids(self, result: dict) -> dict:
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            result["details"] = "/etc/passwd not found"
            return result
        uids = []
        for line in passwd.read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 3:
                uids.append(parts[2])
        dupes = [u for u in set(uids) if uids.count(u) > 1]
        if not dupes:
            result["status"] = "PASS"
            result["details"] = "No duplicate UIDs"
        else:
            result["details"] = f"Duplicate UIDs: {', '.join(dupes)}"
        return result

    def _check_root_only_uid0(self, result: dict) -> dict:
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            result["details"] = "/etc/passwd not found"
            return result
        uid0_users = []
        for line in passwd.read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0":
                uid0_users.append(parts[0])
        if uid0_users == ["root"]:
            result["status"] = "PASS"
            result["details"] = "Only root has UID 0"
        else:
            result["details"] = f"UID 0 accounts: {', '.join(uid0_users)}"
        return result

    def nist_csf_assessment(self, findings: List[dict]) -> dict:
        """Map findings to NIST CSF functions."""
        functions = {
            "Identify": {"score": 100, "items": []},
            "Protect": {"score": 100, "items": []},
            "Detect": {"score": 100, "items": []},
            "Respond": {"score": 100, "items": []},
            "Recover": {"score": 100, "items": []},
        }
        for f in findings:
            cat = f.get("nist_function", "Protect")
            sev = f.get("severity", Severity.LOW)
            d = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 6, "LOW": 2}.get(sev, 2)
            if cat in functions:
                functions[cat]["score"] = max(0, functions[cat]["score"] - d)
                functions[cat]["items"].append(f)
        return functions


# ═══════════════════════════════════════════════════════════════════════════
# EXECUTIVE SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

class ExecutiveSummary:
    """Non-technical security summary with grade and recommendations."""

    @staticmethod
    def generate(findings: List[dict], scores: Dict[str, dict]) -> dict:
        all_scores = [s.get("score", 0) for s in scores.values() if isinstance(s, dict)]
        avg_score = sum(all_scores) / len(all_scores) if all_scores else 0
        grade = RiskScorer._grade(avg_score)

        severity_counts = {}
        for f in findings:
            s = f.get("severity", Severity.LOW)
            severity_counts[s] = severity_counts.get(s, 0) + 1

        top = sorted(findings, key=lambda x: {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}.get(x.get("severity", Severity.LOW), 4))

        recommendations = []
        if severity_counts.get("CRITICAL", 0) > 0:
            recommendations.append("Immediately address all CRITICAL findings — these represent active security risks")
        if severity_counts.get("HIGH", 0) > 0:
            recommendations.append("Schedule remediation of HIGH severity findings within 7 days")
        for f in top[:5]:
            if f.get("recommendation"):
                recommendations.append(f["recommendation"])

        return {
            "score": round(avg_score, 1),
            "grade": grade,
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "top_findings": top[:10],
            "recommendations": recommendations[:10],
            "scores": scores,
        }


# ═══════════════════════════════════════════════════════════════════════════
# PROGRESS ESTIMATOR
# ═══════════════════════════════════════════════════════════════════════════

class ProgressEstimator:
    """ETA calculation for batch operations."""

    def __init__(self):
        self.start_time = time.time()
        self.completed = 0
        self.total = 0

    def start(self, total: int):
        self.start_time = time.time()
        self.completed = 0
        self.total = total

    def tick(self):
        self.completed += 1

    def eta(self) -> str:
        if self.completed == 0:
            return "Calculating..."
        elapsed = time.time() - self.start_time
        rate = self.completed / elapsed
        remaining = (self.total - self.completed) / rate if rate > 0 else 0
        if remaining < 60:
            return f"{remaining:.0f}s"
        elif remaining < 3600:
            return f"{remaining / 60:.1f}m"
        else:
            return f"{remaining / 3600:.1f}h"

    def progress_pct(self) -> float:
        return (self.completed / self.total * 100) if self.total > 0 else 0


# ═══════════════════════════════════════════════════════════════════════════
# REMEDIATION TRACKER
# ═══════════════════════════════════════════════════════════════════════════

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

class UI:
    """Rich-based terminal UI: banners, tables, panels, menus."""

    BANNER = r"""
   ______      __              ______                     __
  / ____/_  __/ /_  ___  _____/ ____/_  ______ __________/ /
 / /   / / / / __ \/ _ \/ ___/ / __/ / / / __ `/ ___/ __  /
/ /___/ /_/ / /_/ /  __/ /  / /_/ / /_/ / /_/ / /  / /_/ /
\____/\__, /_.___/\___/_/   \____/\__,_/\__,_/_/   \__,_/
     /____/           Professional Security Toolkit v{}
"""

    @staticmethod
    def show_banner():
        banner_text = UI.BANNER.format(VERSION)
        panel = Panel(
            Text(banner_text, style="bold cyan"),
            border_style="bright_blue",
            box=box.DOUBLE,
            padding=(0, 2),
        )
        console.print(panel)

    @staticmethod
    def print_success(msg: str):
        console.print(f"  [bold green]✓[/bold green] {msg}")

    @staticmethod
    def print_error(msg: str):
        console.print(f"  [bold red]✗[/bold red] {msg}")

    @staticmethod
    def print_warning(msg: str):
        console.print(f"  [bold yellow]![/bold yellow] {msg}")

    @staticmethod
    def print_info(msg: str):
        console.print(f"  [bold blue]ℹ[/bold blue] {msg}")

    @staticmethod
    def print_section(title: str):
        console.print(f"\n[bold cyan]{'─' * 60}[/bold cyan]")
        console.print(f"[bold cyan]  {title}[/bold cyan]")
        console.print(f"[bold cyan]{'─' * 60}[/bold cyan]")

    @staticmethod
    def print_subsection(title: str):
        console.print(f"\n  [bold yellow]▸ {title}[/bold yellow]")

    @staticmethod
    def print_finding(severity: str, title: str, details: str = ""):
        colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow", "LOW": "green"}
        color = colors.get(severity, "white")
        console.print(f"  [{color}][{severity}][/{color}] {title}")
        if details:
            console.print(f"          {details}")

    @staticmethod
    def print_check(status: str, title: str, details: str = ""):
        if status == "PASS":
            console.print(f"  [green]✓ PASS[/green]  {title}")
        else:
            console.print(f"  [red]✗ FAIL[/red]  {title}")
        if details:
            console.print(f"           [dim]{details}[/dim]")

    @staticmethod
    def print_table(title: str, columns: List[Tuple[str, str]], rows: List[List[str]],
                    show_lines: bool = False):
        if not rows:
            UI.print_warning(f"No data for: {title}")
            return
        table = Table(title=title, box=box.ROUNDED, show_lines=show_lines,
                      title_style="bold cyan", border_style="bright_blue")
        for col_name, col_style in columns:
            table.add_column(col_name, style=col_style)
        for row in rows:
            table.add_row(*[str(c) for c in row])
        console.print(table)

    @staticmethod
    def print_key_value(data: Dict[str, Any], title: str = ""):
        table = Table(box=box.SIMPLE, show_header=False, border_style="bright_blue",
                      title=title if title else None, title_style="bold cyan")
        table.add_column("Key", style="bold yellow", min_width=20)
        table.add_column("Value", style="white")
        for k, v in data.items():
            table.add_row(str(k), str(v))
        console.print(table)

    @staticmethod
    def print_score_panel(score: float, grade: str, title: str = "Security Score"):
        colors = {"A": "green", "B": "bright_green", "C": "yellow", "D": "bright_red", "F": "red"}
        color = colors.get(grade, "white")
        text = Text(f"\n  {score}/100  Grade: {grade}\n", style=f"bold {color}")
        panel = Panel(text, title=title, border_style=color, box=box.DOUBLE)
        console.print(panel)

    @staticmethod
    def print_summary_panel(data: Dict[str, Any], title: str):
        lines = []
        for k, v in data.items():
            lines.append(f"  [bold yellow]{k}:[/bold yellow] {v}")
        content = "\n".join(lines)
        panel = Panel(content, title=title, border_style="bright_blue", box=box.DOUBLE)
        console.print(panel)

    @staticmethod
    def ask_menu(title: str, choices: List[str]) -> Optional[str]:
        try:
            return questionary.select(title, choices=choices).ask()
        except (KeyboardInterrupt, EOFError):
            return None

    @staticmethod
    def ask_input(prompt: str, validate: callable = None) -> Optional[str]:
        try:
            val = Prompt.ask(f"  {prompt}")
            if validate and val and not validate(val):
                UI.print_error("Invalid input")
                return None
            return val
        except (KeyboardInterrupt, EOFError):
            return None

    @staticmethod
    def confirm(prompt: str) -> bool:
        try:
            return Confirm.ask(f"  {prompt}")
        except (KeyboardInterrupt, EOFError):
            return False

    @staticmethod
    def print_port_scan_results(target: str, results: List[dict]):
        if not results:
            UI.print_warning(f"No open ports found on {target}")
            return
        table = Table(title=f"Port Scan Results: {target}", box=box.ROUNDED,
                      title_style="bold cyan", border_style="bright_blue")
        table.add_column("Port", style="bold yellow")
        table.add_column("State", style="green")
        table.add_column("Service", style="white")
        table.add_column("Banner", style="dim")
        for r in results:
            table.add_row(
                str(r.get("port", "")),
                r.get("state", "open"),
                r.get("service", "unknown"),
                r.get("banner", "")[:60],
            )
        console.print(table)

    @staticmethod
    def print_dns_results(domain: str, records: Dict[str, List]):
        table = Table(title=f"DNS Records: {domain}", box=box.ROUNDED,
                      title_style="bold cyan", border_style="bright_blue")
        table.add_column("Type", style="bold yellow")
        table.add_column("Value", style="white")
        for rtype, values in records.items():
            for v in values:
                table.add_row(rtype, str(v))
        console.print(table)

    @staticmethod
    def print_connections_table(connections: List[dict]):
        if not connections:
            UI.print_warning("No connections found")
            return
        table = Table(title="Network Connections", box=box.ROUNDED,
                      title_style="bold cyan", border_style="bright_blue")
        table.add_column("Proto", style="bold")
        table.add_column("Local Address", style="cyan")
        table.add_column("Remote Address", style="yellow")
        table.add_column("State", style="green")
        table.add_column("PID/Process", style="white")
        for c in connections[:100]:
            state_style = "red" if c.get("suspicious") else "green"
            table.add_row(
                c.get("proto", ""),
                c.get("local", ""),
                c.get("remote", ""),
                f"[{state_style}]{c.get('state', '')}[/{state_style}]",
                c.get("process", ""),
            )
        console.print(table)

    @staticmethod
    def print_process_table(processes: List[dict]):
        if not processes:
            return
        table = Table(title="Suspicious Processes", box=box.ROUNDED,
                      title_style="bold red", border_style="red")
        table.add_column("PID", style="bold yellow")
        table.add_column("User", style="cyan")
        table.add_column("CPU%", style="white")
        table.add_column("MEM%", style="white")
        table.add_column("Command", style="white")
        table.add_column("Reason", style="red")
        for p in processes[:50]:
            table.add_row(
                str(p.get("pid", "")),
                p.get("user", ""),
                f"{p.get('cpu', 0):.1f}",
                f"{p.get('mem', 0):.1f}",
                p.get("cmd", "")[:60],
                p.get("reason", ""),
            )
        console.print(table)

    @staticmethod
    def print_log_events(events: List[dict], title: str = "Log Events"):
        if not events:
            UI.print_warning(f"No events found for: {title}")
            return
        table = Table(title=title, box=box.ROUNDED,
                      title_style="bold cyan", border_style="bright_blue")
        table.add_column("Time", style="dim")
        table.add_column("Source", style="bold yellow")
        table.add_column("Severity", style="white")
        table.add_column("Message", style="white")
        for e in events[:100]:
            sev = e.get("severity", Severity.INFO)
            colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow",
                      "LOW": "green", "INFO": "blue"}
            color = colors.get(sev, "white")
            table.add_row(
                e.get("timestamp", ""),
                e.get("source", ""),
                f"[{color}]{sev}[/{color}]",
                e.get("message", "")[:80],
            )
        console.print(table)

    @staticmethod
    def print_remediation_table(items: List[dict]):
        if not items:
            UI.print_info("No remediation items")
            return
        table = Table(title="Remediation Tracker", box=box.ROUNDED,
                      title_style="bold cyan", border_style="bright_blue")
        table.add_column("ID", style="bold")
        table.add_column("Severity", style="white")
        table.add_column("Title", style="white")
        table.add_column("Status", style="white")
        table.add_column("Due Date", style="dim")
        for item in items:
            sev = item.get("severity", Severity.LOW)
            colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow", "LOW": "green"}
            color = colors.get(sev, "white")
            st = item.get("status", "open")
            st_color = "green" if st == "resolved" else "yellow" if st == "in-progress" else "red"
            table.add_row(
                str(item.get("id", "")),
                f"[{color}]{sev}[/{color}]",
                item.get("title", "")[:50],
                f"[{st_color}]{st}[/{st_color}]",
                item.get("due_date", "N/A"),
            )
        console.print(table)

    @staticmethod
    def print_threat_intel(data: dict, source: str):
        """Display threat intelligence results."""
        panel_data = {}
        if source == "virustotal":
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            panel_data = {
                "Owner": attrs.get("as_owner", "N/A"),
                "ASN": attrs.get("asn", "N/A"),
                "Country": attrs.get("country", "N/A"),
                "Malicious": stats.get("malicious", 0),
                "Suspicious": stats.get("suspicious", 0),
                "Harmless": stats.get("harmless", 0),
                "Undetected": stats.get("undetected", 0),
                "Reputation": attrs.get("reputation", "N/A"),
            }
        elif source == "abuseipdb":
            d = data.get("data", {})
            panel_data = {
                "IP": d.get("ipAddress", "N/A"),
                "Abuse Score": f"{d.get('abuseConfidenceScore', 0)}%",
                "ISP": d.get("isp", "N/A"),
                "Country": d.get("countryCode", "N/A"),
                "Domain": d.get("domain", "N/A"),
                "Total Reports": d.get("totalReports", 0),
                "Distinct Users": d.get("numDistinctUsers", 0),
                "Whitelisted": d.get("isWhitelisted", False),
            }
        UI.print_key_value(panel_data, f"Threat Intelligence: {source.upper()}")


# ═══════════════════════════════════════════════════════════════════════════
# CYBERGUARD TOOLKIT (Main Class)
# ═══════════════════════════════════════════════════════════════════════════

class CyberGuardToolkit:
    """Main toolkit class: menu navigation, orchestration of all categories."""

    def __init__(self):
        self.config = Config()
        self.cmd = SystemCommandRunner(self.config.logger)
        self.threat_intel = ThreatIntelAPI(self.config)
        self.exporter = ResultExporter(self.config.results_dir, self.config.logger)
        self.baseline_mgr = BaselineManager(self.config.logger)
        self.alert_mgr = AlertManager(self.config)
        self.compliance = ComplianceChecker(self.cmd, self.config.logger)
        self.remediation = RemediationTracker(self.config.logger)
        self.evidence = EvidenceCollector(self.cmd, self.config.logger)
        self.ui = UI()
        self.findings: List[dict] = []
        self.scores: Dict[str, dict] = {}

    def run(self):
        UI.show_banner()
        console.print(f"  [dim]Session: {self.config.session_id}[/dim]")
        console.print(f"  [dim]Results: {self.config.results_dir}[/dim]")
        console.print()
        self._check_dependencies()

        while True:
            try:
                choice = UI.ask_menu(
                    "CyberGuard Main Menu",
                    [
                        "1) Network Security",
                        "2) System Hardening",
                        "3) Vulnerability Assessment",
                        "4) Monitoring & SIEM",
                        "5) Threat Intelligence",
                        "6) Forensics & IR",
                        "7) Reporting & Compliance",
                        "8) Automated Workflows",
                        "9) Settings & Configuration",
                        "0) Exit",
                    ],
                )
                if not choice or choice.startswith("0"):
                    console.print("\n[bold cyan]Goodbye! Stay secure.[/bold cyan]\n")
                    break
                num = choice.split(")")[0].strip()
                handler = {
                    "1": self._network_security_menu,
                    "2": self._system_hardening_menu,
                    "3": self._vuln_assessment_menu,
                    "4": self._monitoring_menu,
                    "5": self._threat_intel_menu,
                    "6": self._forensics_menu,
                    "7": self._reporting_menu,
                    "8": self._workflows_menu,
                    "9": self._settings_menu,
                }.get(num)
                if handler:
                    handler()
            except KeyboardInterrupt:
                console.print("\n")
                continue
            except Exception as e:
                UI.print_error(f"Error: {e}")
                self.config.logger.error(f"Menu error: {e}", exc_info=True)

    def _check_dependencies(self):
        deps = {"psutil": HAS_PSUTIL, "dnspython": HAS_DNSPYTHON, "cryptography": HAS_CRYPTOGRAPHY}
        missing = [k for k, v in deps.items() if not v]
        if missing:
            UI.print_warning(f"Optional dependencies not installed: {', '.join(missing)}")

    def _add_finding(self, title: str, severity: str, description: str = "",
                     recommendation: str = "", category: str = "",
                     nist_function: str = "Protect"):
        self.findings.append({
            "title": title, "severity": severity, "description": description,
            "recommendation": recommendation, "category": category,
            "nist_function": nist_function,
            "timestamp": datetime.now().isoformat(),
        })

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 1: NETWORK SECURITY
    # ═══════════════════════════════════════════════════════════════════

    def _network_security_menu(self):
        while True:
            choice = UI.ask_menu("Network Security", [
                "1) Port Scanner",
                "2) Service Detection",
                "3) DNS Reconnaissance",
                "4) Firewall Rule Audit",
                "5) ARP Monitor",
                "6) Network Connection Monitor",
                "7) VPN/Tunnel Detection",
                "8) Bandwidth & Traffic Summary",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._port_scanner, "2": self._service_detection,
                "3": self._dns_recon, "4": self._firewall_audit,
                "5": self._arp_monitor, "6": self._network_connections,
                "7": self._vpn_detection, "8": self._bandwidth_summary,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")
                    self.config.logger.error(f"Network error: {e}", exc_info=True)

    def _port_scanner(self):
        UI.print_section("Port Scanner")
        target = UI.ask_input("Target IP or hostname")
        if not target:
            return
        target = target.strip()
        if not InputValidator.validate_ip(target) and not InputValidator.validate_domain(target):
            UI.print_error("Invalid target. Enter an IP address or domain.")
            return

        scan_type = UI.ask_menu("Scan type:", [
            "Quick (top 65 ports)",
            "Common (top 1000 ports)",
            "Full (1-65535)",
            "Custom range",
        ])
        if not scan_type:
            return

        if scan_type.startswith("Quick"):
            ports = TOP_100_PORTS
        elif scan_type.startswith("Common"):
            ports = TOP_1000_PORTS
        elif scan_type.startswith("Full"):
            ports = list(range(1, 65536))
        else:
            pr = UI.ask_input("Port range (e.g., 1-1000)")
            if not pr:
                return
            parsed = InputValidator.validate_port_range(pr)
            if not parsed:
                UI.print_error("Invalid port range")
                return
            ports = list(range(parsed[0], parsed[1] + 1))

        timeout_val = 1.0
        if len(ports) > 1000:
            timeout_val = 0.5

        results = []
        common_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
            139: "netbios", 143: "imap", 161: "snmp", 389: "ldap",
            443: "https", 445: "smb", 465: "smtps", 514: "syslog",
            587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
            8080: "http-proxy", 8443: "https-alt", 9090: "web-mgmt",
            9200: "elasticsearch", 27017: "mongodb",
        }

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task(f"Scanning {target}", total=len(ports))
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout_val)
                    rc = sock.connect_ex((target, port))
                    if rc == 0:
                        service = common_services.get(port, "unknown")
                        banner = ""
                        try:
                            sock.settimeout(2)
                            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
                        except Exception as e:
                            self.config.logger.debug("Banner grab failed for %s:%s: %s", target, port, e)
                            pass
                        results.append({
                            "port": port, "state": "open",
                            "service": service, "banner": banner,
                        })
                    sock.close()
                except Exception as e:
                    self.config.logger.debug("Port scan connect failed for %s:%s: %s", target, port, e)
                    pass
                progress.advance(task)

        UI.print_port_scan_results(target, results)
        self.config.save_session_history("port_scan", f"{target}: {len(results)} open ports")

        if results:
            suspicious = [r for r in results if r["port"] in SUSPICIOUS_PORTS]
            if suspicious:
                for s in suspicious:
                    self._add_finding(
                        f"Suspicious port {s['port']} open on {target}",
                        "HIGH",
                        f"Port {s['port']} ({s['service']}) is commonly used by malware",
                        "Investigate and close if not needed",
                        "Network", "Detect",
                    )
            self.exporter.ask_export(
                results, f"port_scan_{target}",
                rows=results,
                txt="\n".join(f"Port {r['port']}: {r['service']}" for r in results),
            )

    def _service_detection(self):
        UI.print_section("Service Detection")
        choice = UI.ask_menu("Detection method:", [
            "Local services (ss)",
            "Remote scan (nmap -sV)",
        ])
        if not choice:
            return

        if choice.startswith("Local"):
            rc, out, _ = self.cmd.run(["ss", "-tlnp"], timeout=15)
            if rc != 0:
                UI.print_error("Failed to run ss command")
                return
            services = []
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    local = parts[3]
                    process = parts[5] if len(parts) > 5 else ""
                    process_match = re.search(r'"([^"]+)"', process)
                    proc_name = process_match.group(1) if process_match else "unknown"
                    services.append({
                        "state": parts[0], "local_addr": local,
                        "service": proc_name,
                    })
            rows = [[s["local_addr"], s["service"], s["state"]] for s in services]
            UI.print_table("Local Listening Services",
                           [("Address", "cyan"), ("Service", "white"), ("State", "green")],
                           rows)
            if services:
                self.exporter.ask_export(services, "local_services", rows=services)
        else:
            target = UI.ask_input("Target IP or hostname")
            if not target:
                return
            if not self.cmd.has_command("nmap"):
                UI.print_error("nmap is not installed. Install with: sudo apt install nmap")
                return
            UI.print_info(f"Running nmap service detection on {target}...")
            rc, out, err = self.cmd.run(
                ["nmap", "-sV", "--top-ports", "100", "-T4", target],
                timeout=120,
            )
            if rc == 0:
                console.print(f"\n{out}")
            else:
                UI.print_error(f"nmap failed: {err}")

    def _dns_recon(self):
        UI.print_section("DNS Reconnaissance")
        if not HAS_DNSPYTHON:
            UI.print_error("dnspython not installed. Install with: pip install dnspython")
            return

        domain = UI.ask_input("Target domain")
        if not domain or not InputValidator.validate_domain(domain.strip()):
            UI.print_error("Invalid domain")
            return
        domain = domain.strip()

        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Querying DNS records...", total=len(record_types))
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except Exception as e:
                    self.config.logger.debug("DNS %s lookup failed: %s", rtype, e)
                    pass
                progress.advance(task)

        UI.print_dns_results(domain, records)

        # Subdomain brute force
        if UI.confirm("Run subdomain enumeration?"):
            common_subs = [
                "www", "mail", "ftp", "admin", "blog", "dev", "staging",
                "api", "app", "cdn", "docs", "git", "jenkins", "jira",
                "login", "m", "media", "ns1", "ns2", "portal", "shop",
                "smtp", "ssh", "test", "vpn", "webmail", "wiki", "mx",
                "db", "backup", "monitoring", "status", "internal",
            ]
            found_subs = []
            with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                          BarColumn(), TextColumn("{task.percentage:>3.0f}%")) as progress:
                task = progress.add_task("Enumerating subdomains", total=len(common_subs))
                for sub in common_subs:
                    full = f"{sub}.{domain}"
                    try:
                        answers = dns.resolver.resolve(full, "A")
                        ips = [str(r) for r in answers]
                        found_subs.append({"subdomain": full, "ips": ips})
                    except Exception as e:
                        self.config.logger.debug("Subdomain %s failed: %s", full, e)
                        pass
                    progress.advance(task)

            if found_subs:
                rows = [[s["subdomain"], ", ".join(s["ips"])] for s in found_subs]
                UI.print_table("Discovered Subdomains",
                               [("Subdomain", "cyan"), ("IP Addresses", "white")], rows)

        all_data = {"domain": domain, "records": records}
        self.config.save_session_history("dns_recon", f"{domain}: {sum(len(v) for v in records.values())} records")
        self.exporter.ask_export(all_data, f"dns_{domain}", rows=[
            {"type": t, "value": v} for t, vals in records.items() for v in vals
        ])

    def _firewall_audit(self):
        UI.print_section("Firewall Rule Audit")
        findings = []

        # Check ufw
        rc, out, _ = self.cmd.run(["ufw", "status", "verbose"], timeout=10)
        if rc == 0:
            UI.print_subsection("UFW Status")
            console.print(f"\n{out}")
            if "inactive" in out.lower():
                findings.append({"title": "UFW firewall is inactive", "severity": Severity.HIGH,
                                 "recommendation": "Enable with: sudo ufw enable"})
                self._add_finding("Firewall is inactive", "HIGH",
                                  "UFW firewall is not enabled",
                                  "Enable with: sudo ufw enable", "Network", "Protect")
            if "allow" in out.lower() and "anywhere" in out.lower():
                wide_rules = [l for l in out.splitlines() if "ALLOW" in l and "Anywhere" in l]
                if wide_rules:
                    findings.append({"title": f"{len(wide_rules)} wide-open ALLOW rules",
                                     "severity": Severity.MEDIUM})
        else:
            # Try iptables
            rc2, out2, _ = self.cmd.run(["iptables", "-L", "-n", "--line-numbers"], timeout=10)
            if rc2 == 0:
                UI.print_subsection("iptables Rules")
                console.print(f"\n{out2}")
            else:
                UI.print_warning("Cannot read firewall status (try with sudo)")

        if findings:
            for f in findings:
                UI.print_finding(f["severity"], f["title"])

    def _arp_monitor(self):
        UI.print_section("ARP Monitor")
        rc, out, _ = self.cmd.run(["ip", "neigh", "show"], timeout=10)
        if rc != 0:
            UI.print_error("Failed to read ARP table")
            return

        entries = []
        mac_to_ips: Dict[str, List[str]] = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                mac = parts[4] if parts[4] != "FAILED" else "N/A"
                state = parts[-1]
                entries.append({"ip": ip, "mac": mac, "state": state})
                if mac != "N/A":
                    mac_to_ips.setdefault(mac, []).append(ip)

        rows = [[e["ip"], e["mac"], e["state"]] for e in entries]
        UI.print_table("ARP Table",
                       [("IP Address", "cyan"), ("MAC Address", "yellow"), ("State", "green")],
                       rows)

        # Check for duplicate MACs (potential ARP spoofing)
        dupes = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
        if dupes:
            UI.print_warning("Potential ARP spoofing detected!")
            for mac, ips in dupes.items():
                UI.print_finding("HIGH", f"MAC {mac} mapped to multiple IPs: {', '.join(ips)}")
                self._add_finding(
                    f"Duplicate MAC detected: {mac}", "HIGH",
                    f"MAC {mac} is associated with IPs: {', '.join(ips)}",
                    "Investigate for ARP spoofing", "Network", "Detect",
                )

    def _network_connections(self):
        UI.print_section("Network Connection Monitor")
        rc, out, _ = self.cmd.run(["ss", "-tunap"], timeout=15)
        if rc != 0:
            UI.print_error("Failed to run ss command")
            return

        connections = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0]
                local = parts[3]
                remote = parts[4]
                state = parts[1] if len(parts) > 1 else ""
                process = parts[5] if len(parts) > 5 else ""
                process_match = re.search(r'"([^"]+)"', process)
                proc_name = process_match.group(1) if process_match else ""

                suspicious = False
                # Check for suspicious remote ports
                try:
                    remote_port = int(remote.rsplit(":", 1)[-1])
                    if remote_port in SUSPICIOUS_PORTS:
                        suspicious = True
                except (ValueError, IndexError):
                    pass

                connections.append({
                    "proto": proto, "local": local, "remote": remote,
                    "state": state, "process": proc_name, "suspicious": suspicious,
                })

        UI.print_connections_table(connections)

        suspicious_conns = [c for c in connections if c["suspicious"]]
        if suspicious_conns:
            UI.print_warning(f"Found {len(suspicious_conns)} suspicious connection(s)!")
            for c in suspicious_conns:
                self._add_finding(
                    f"Suspicious connection to {c['remote']}", "HIGH",
                    f"Process '{c['process']}' connected to suspicious port",
                    "Investigate the connection and process", "Network", "Detect",
                )

        self.config.save_session_history("connections", f"{len(connections)} active connections")

    def _vpn_detection(self):
        UI.print_section("VPN/Tunnel Detection")
        vpns_found = []

        # Check interfaces
        rc, out, _ = self.cmd.run(["ip", "link", "show"], timeout=10)
        if rc == 0:
            for line in out.splitlines():
                for vpn_type in ["tun", "tap", "wg", "ppp", "vti", "gre"]:
                    if f"{vpn_type}" in line.lower():
                        iface = line.split(":")[1].strip().split("@")[0] if ":" in line else "unknown"
                        vpns_found.append({"type": vpn_type, "interface": iface})

        # WireGuard
        if self.cmd.has_command("wg"):
            rc, out, _ = self.cmd.run(["wg", "show"], timeout=10)
            if rc == 0 and out.strip():
                vpns_found.append({"type": "WireGuard", "interface": "wg", "details": out[:200]})

        # OpenVPN
        rc, out, _ = self.cmd.run(["pgrep", "-a", "openvpn"], timeout=5)
        if rc == 0 and out.strip():
            vpns_found.append({"type": "OpenVPN", "interface": "tun", "details": out[:200]})

        # SSH tunnels
        rc, out, _ = self.cmd.run(["ss", "-tnp"], timeout=10)
        if rc == 0:
            ssh_tunnels = [l for l in out.splitlines() if "ssh" in l.lower() and "ESTAB" in l]
            if ssh_tunnels:
                vpns_found.append({"type": "SSH Tunnel", "interface": "N/A",
                                   "details": f"{len(ssh_tunnels)} SSH tunnel(s)"})

        if vpns_found:
            rows = [[v["type"], v.get("interface", "N/A"), v.get("details", "")[:60]]
                    for v in vpns_found]
            UI.print_table("VPN/Tunnels Detected",
                           [("Type", "cyan"), ("Interface", "yellow"), ("Details", "white")],
                           rows)
        else:
            UI.print_info("No VPN/tunnel interfaces detected")

    def _bandwidth_summary(self):
        UI.print_section("Bandwidth & Traffic Summary")

        # /proc/net/dev
        content = self.cmd.read_proc_file("/proc/net/dev")
        if content:
            interfaces = []
            for line in content.splitlines()[2:]:
                parts = line.split()
                if len(parts) >= 10:
                    iface = parts[0].rstrip(":")
                    rx_bytes = int(parts[1])
                    tx_bytes = int(parts[9])
                    interfaces.append({
                        "interface": iface,
                        "rx_bytes": rx_bytes,
                        "tx_bytes": tx_bytes,
                        "rx_human": self._human_bytes(rx_bytes),
                        "tx_human": self._human_bytes(tx_bytes),
                    })
            rows = [[i["interface"], i["rx_human"], i["tx_human"]]
                    for i in interfaces if i["rx_bytes"] > 0 or i["tx_bytes"] > 0]
            UI.print_table("Network Interface Traffic",
                           [("Interface", "cyan"), ("RX", "green"), ("TX", "yellow")],
                           rows)

        # ss -s
        rc, out, _ = self.cmd.run(["ss", "-s"], timeout=10)
        if rc == 0:
            UI.print_subsection("Socket Statistics")
            console.print(f"\n{out}")

    @staticmethod
    def _human_bytes(n: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if abs(n) < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} PB"

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 2: SYSTEM HARDENING
    # ═══════════════════════════════════════════════════════════════════

    def _system_hardening_menu(self):
        while True:
            choice = UI.ask_menu("System Hardening", [
                "1) OS Security Audit",
                "2) Service Hardening",
                "3) File Permission Auditor",
                "4) User & PAM Security",
                "5) Kernel Parameter Checker",
                "6) SSH Hardening Audit",
                "7) Firewall Config Audit",
                "8) Full Hardening Report",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._os_security_audit, "2": self._service_hardening,
                "3": self._file_permission_audit, "4": self._user_pam_security,
                "5": self._kernel_params, "6": self._ssh_hardening,
                "7": self._firewall_config_audit, "8": self._full_hardening_report,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")
                    self.config.logger.error(f"Hardening error: {e}", exc_info=True)

    def _os_security_audit(self):
        UI.print_section("OS Security Audit")
        checks = []

        # Kernel version
        rc, out, _ = self.cmd.run(["uname", "-r"], timeout=5)
        kernel = out.strip() if rc == 0 else "Unknown"
        UI.print_info(f"Kernel: {kernel}")

        # ASLR
        val = self.cmd.read_sysctl("kernel.randomize_va_space")
        passed = val == "2"
        checks.append({"title": "ASLR (Address Space Layout Randomization)", "status": "PASS" if passed else "FAIL",
                        "details": f"Value: {val} (expected: 2)"})
        if not passed:
            self._add_finding("ASLR not fully enabled", "HIGH",
                              f"kernel.randomize_va_space = {val} (should be 2)",
                              "Set: sysctl -w kernel.randomize_va_space=2", "Hardening", "Protect")

        # Core dumps
        val = self.cmd.read_sysctl("fs.suid_dumpable")
        passed = val == "0"
        checks.append({"title": "SUID Core Dumps Disabled", "status": "PASS" if passed else "FAIL",
                        "details": f"Value: {val}"})

        # Secure Boot
        sb_path = Path("/sys/firmware/efi/efivars")
        sb = sb_path.exists()
        checks.append({"title": "EFI/UEFI Boot", "status": "PASS" if sb else "FAIL",
                        "details": "EFI boot detected" if sb else "Legacy BIOS boot"})

        # Pending updates
        rc, out, _ = self.cmd.run(["apt", "list", "--upgradable"], timeout=30)
        if rc == 0:
            updates = [l for l in out.splitlines()[1:] if l.strip()]
            security_updates = [u for u in updates if "security" in u.lower()]
            checks.append({"title": "System Updates", "status": "PASS" if not security_updates else "FAIL",
                            "details": f"{len(updates)} pending ({len(security_updates)} security)"})
            if security_updates:
                self._add_finding(f"{len(security_updates)} pending security updates", "HIGH",
                                  "Security updates available",
                                  "Run: sudo apt update && sudo apt upgrade", "Hardening", "Protect")

        # dmesg restriction
        val = self.cmd.read_sysctl("kernel.dmesg_restrict")
        passed = val == "1"
        checks.append({"title": "dmesg Restricted", "status": "PASS" if passed else "FAIL",
                        "details": f"Value: {val}"})

        # kptr_restrict
        val = self.cmd.read_sysctl("kernel.kptr_restrict")
        passed = val in ("1", "2")
        checks.append({"title": "Kernel Pointer Restriction", "status": "PASS" if passed else "FAIL",
                        "details": f"Value: {val}"})

        for c in checks:
            UI.print_check(c["status"], c["title"], c["details"])

        return checks

    def _service_hardening(self):
        UI.print_section("Service Hardening Audit")
        checks = []

        rc, out, _ = self.cmd.run(["systemctl", "list-units", "--type=service", "--state=running",
                                    "--no-pager", "--no-legend"], timeout=15)
        if rc != 0:
            UI.print_error("Cannot list services")
            return checks

        running_services = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                svc = parts[0].replace(".service", "")
                running_services.append(svc)

        unnecessary = [s for s in running_services if s in UNNECESSARY_SERVICES]
        if unnecessary:
            for s in unnecessary:
                UI.print_finding("MEDIUM", f"Unnecessary service running: {s}",
                                 "Consider disabling if not needed")
                checks.append({"title": f"Unnecessary service: {s}", "status": "FAIL",
                                "details": "Running but may not be needed"})
                self._add_finding(f"Unnecessary service: {s}", "MEDIUM",
                                  f"Service {s} is running but may not be needed",
                                  f"Disable with: sudo systemctl disable --now {s}", "Hardening", "Protect")
        else:
            UI.print_success("No common unnecessary services detected")

        # Check for services listening on 0.0.0.0
        rc, out, _ = self.cmd.run(["ss", "-tlnp"], timeout=10)
        if rc == 0:
            wildcard_services = []
            for line in out.splitlines()[1:]:
                if "0.0.0.0:*" in line or "*:*" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        addr = parts[3]
                        proc = parts[-1] if len(parts) > 5 else ""
                        wildcard_services.append(f"{addr} ({proc})")
            if wildcard_services:
                UI.print_warning(f"{len(wildcard_services)} service(s) listening on all interfaces")
                for ws in wildcard_services[:10]:
                    UI.print_info(f"  {ws}")

        return checks

    def _file_permission_audit(self):
        UI.print_section("File Permission Auditor")
        findings_list = []

        # SUID files
        UI.print_subsection("SUID/SGID Files")
        rc, out, _ = self.cmd.run(
            ["find", "/usr", "/bin", "/sbin", "-maxdepth", "3", "-perm", "-4000", "-type", "f"],
            timeout=30,
        )
        known_suid = {
            "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
            "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/mount",
            "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/crontab",
            "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        }
        if rc == 0:
            suid_files = [f.strip() for f in out.splitlines() if f.strip()]
            unknown_suid = [f for f in suid_files if f not in known_suid]
            UI.print_info(f"Total SUID files: {len(suid_files)}")
            if unknown_suid:
                UI.print_warning(f"Non-standard SUID files: {len(unknown_suid)}")
                for f in unknown_suid[:20]:
                    UI.print_finding("MEDIUM", f"Non-standard SUID: {f}")
                    findings_list.append({"title": f"SUID: {f}", "severity": Severity.MEDIUM})

        # World-writable files in /etc
        UI.print_subsection("World-Writable Files")
        rc, out, _ = self.cmd.run(
            ["find", "/etc", "-maxdepth", "2", "-type", "f", "-perm", "-0002"],
            timeout=15,
        )
        if rc == 0:
            ww_files = [f.strip() for f in out.splitlines() if f.strip()]
            if ww_files:
                UI.print_warning(f"World-writable files in /etc: {len(ww_files)}")
                for f in ww_files[:10]:
                    UI.print_finding("HIGH", f"World-writable: {f}")
                    self._add_finding(f"World-writable file: {f}", "HIGH",
                                      "File is writable by any user",
                                      f"Fix: chmod o-w {f}", "Hardening", "Protect")
            else:
                UI.print_success("No world-writable files in /etc")

        # Critical file permissions
        UI.print_subsection("Critical File Permissions")
        critical_files = {
            "/etc/passwd": 0o644, "/etc/shadow": 0o640,
            "/etc/group": 0o644, "/etc/gshadow": 0o640,
            "/etc/ssh/sshd_config": 0o600,
        }
        for fpath, expected in critical_files.items():
            p = Path(fpath)
            if p.exists():
                mode = p.stat().st_mode & 0o777
                passed = mode <= expected
                UI.print_check(
                    "PASS" if passed else "FAIL",
                    f"{fpath}: {oct(mode)}",
                    f"Expected: <= {oct(expected)}" if not passed else "",
                )
                if not passed:
                    self._add_finding(f"Insecure permissions on {fpath}", "HIGH",
                                      f"Current: {oct(mode)}, Expected: <= {oct(expected)}",
                                      f"Fix: chmod {oct(expected)} {fpath}", "Hardening", "Protect")

        return findings_list

    def _user_pam_security(self):
        UI.print_section("User & PAM Security")
        checks = []

        # UID 0 users
        passwd = Path("/etc/passwd")
        if passwd.exists():
            uid0_users = []
            no_shell_users = 0
            for line in passwd.read_text(errors="replace").splitlines():
                parts = line.split(":")
                if len(parts) >= 7:
                    if parts[2] == "0" and parts[0] != "root":
                        uid0_users.append(parts[0])
                    if parts[6] in ("/usr/sbin/nologin", "/bin/false"):
                        no_shell_users += 1

            if uid0_users:
                UI.print_finding("CRITICAL", f"Non-root UID 0 accounts: {', '.join(uid0_users)}")
                self._add_finding("Non-root UID 0 accounts", "CRITICAL",
                                  f"Accounts with UID 0: {', '.join(uid0_users)}",
                                  "Remove or change UID", "Hardening", "Protect")
                checks.append({"title": "Root-only UID 0", "status": "FAIL"})
            else:
                UI.print_success("Only root has UID 0")
                checks.append({"title": "Root-only UID 0", "status": "PASS"})

        # sudo NOPASSWD
        sudoers_dir = Path("/etc/sudoers.d")
        nopasswd_found = False
        for sp in [Path("/etc/sudoers")] + list(sudoers_dir.glob("*") if sudoers_dir.exists() else []):
            try:
                content = sp.read_text(errors="replace")
                if "NOPASSWD" in content:
                    nopasswd_found = True
                    break
            except (OSError, PermissionError):
                continue

        if nopasswd_found:
            UI.print_finding("MEDIUM", "NOPASSWD found in sudoers configuration")
            checks.append({"title": "sudo NOPASSWD", "status": "FAIL"})
        else:
            UI.print_success("No NOPASSWD in sudoers")
            checks.append({"title": "sudo NOPASSWD", "status": "PASS"})

        # Password policy
        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            content = login_defs.read_text(errors="replace")
            for param, expected in [("PASS_MAX_DAYS", "365"), ("PASS_MIN_DAYS", "1"),
                                     ("PASS_MIN_LEN", "8")]:
                for line in content.splitlines():
                    if line.strip().startswith(param):
                        val = line.split()[-1]
                        UI.print_info(f"{param} = {val}")

        return checks

    def _kernel_params(self):
        UI.print_section("Kernel Parameter Security Check")
        results = []
        for param, info in KERNEL_SECURITY_PARAMS.items():
            val = self.cmd.read_sysctl(param)
            passed = val == info["expected"]
            results.append({
                "param": param, "current": val, "expected": info["expected"],
                "status": "PASS" if passed else "FAIL", "desc": info["desc"],
            })
            UI.print_check("PASS" if passed else "FAIL", info["desc"],
                           f"{param} = {val}" if not passed else "")
            if not passed:
                self._add_finding(f"Insecure kernel parameter: {param}", "MEDIUM",
                                  f"Current: {val}, Expected: {info['expected']}",
                                  f"Fix: sysctl -w {param}={info['expected']}", "Hardening", "Protect")

        passed = sum(1 for r in results if r["status"] == "PASS")
        total = len(results)
        score = RiskScorer.score_compliance(passed, total)
        UI.print_score_panel(score["score"], score["grade"], "Kernel Security Score")
        self.scores["kernel"] = score
        return results

    def _ssh_hardening(self):
        UI.print_section("SSH Hardening Audit")
        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            UI.print_error("sshd_config not found")
            return []

        try:
            content = sshd_config.read_text(errors="replace")
        except PermissionError:
            UI.print_error("Cannot read sshd_config (permission denied)")
            return []

        config_values = {}
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                config_values[parts[0]] = parts[1]

        results = []
        for param, info in SSH_SECURITY_PARAMS.items():
            val = config_values.get(param, "not set")
            expected = info["expected"]
            compare = info.get("compare", "eq")
            passed = False

            if val == "not set":
                passed = False
            elif compare == "lte":
                try:
                    passed = int(val) <= int(expected)
                except ValueError:
                    passed = False
            else:
                passed = val.lower() == expected.lower()

            results.append({
                "param": param, "current": val, "expected": expected,
                "status": "PASS" if passed else "FAIL",
                "severity": info["severity"],
            })
            UI.print_check("PASS" if passed else "FAIL", f"{param} = {val}",
                           f"Expected: {expected}" if not passed else "")
            if not passed:
                self._add_finding(f"SSH: {param} = {val}", info["severity"],
                                  f"Expected: {expected}",
                                  f"Set '{param} {expected}' in sshd_config", "Hardening", "Protect")

        passed_count = sum(1 for r in results if r["status"] == "PASS")
        score = RiskScorer.score_compliance(passed_count, len(results))
        UI.print_score_panel(score["score"], score["grade"], "SSH Security Score")
        self.scores["ssh"] = score
        return results

    def _firewall_config_audit(self):
        UI.print_section("Firewall Configuration Audit")
        self._firewall_audit()

    def _full_hardening_report(self):
        UI.print_section("Full System Hardening Report")
        all_checks = {}

        UI.print_info("Running OS Security Audit...")
        all_checks["OS Security"] = self._os_security_audit() or []

        UI.print_info("Running Service Hardening...")
        all_checks["Services"] = self._service_hardening() or []

        UI.print_info("Running File Permission Audit...")
        all_checks["File Permissions"] = self._file_permission_audit() or []

        UI.print_info("Running User & PAM Security...")
        all_checks["User Security"] = self._user_pam_security() or []

        UI.print_info("Running Kernel Parameter Check...")
        all_checks["Kernel Parameters"] = self._kernel_params() or []

        UI.print_info("Running SSH Hardening Audit...")
        all_checks["SSH Security"] = self._ssh_hardening() or []

        # Calculate overall score
        all_findings = [f for f in self.findings if f.get("category") == "Hardening"]
        score = RiskScorer.score_host(all_findings)
        UI.print_score_panel(score["score"], score["grade"], "Overall Hardening Score")
        self.scores["hardening"] = score
        self.config.save_score("hardening", score["score"])

        # Generate HTML report
        html = HTMLReportGenerator.hardening_report(all_checks, score)
        self.exporter.ask_export(
            {"checks": all_checks, "score": score},
            "hardening_report",
            html=html,
            txt=self._generate_hardening_txt(all_checks, score),
        )

    def _generate_hardening_txt(self, checks: dict, score: dict) -> str:
        lines = [f"System Hardening Report", f"Score: {score['score']}/100 (Grade {score['grade']})", ""]
        for cat, items in checks.items():
            lines.append(f"\n--- {cat} ---")
            for item in items:
                st = item.get("status", "?")
                lines.append(f"  [{st}] {item.get('title', '')}: {item.get('details', '')}")
        return "\n".join(lines)

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 3: VULNERABILITY ASSESSMENT
    # ═══════════════════════════════════════════════════════════════════

    def _vuln_assessment_menu(self):
        while True:
            choice = UI.ask_menu("Vulnerability Assessment", [
                "1) CVE Lookup",
                "2) SSL/TLS Analyzer",
                "3) Software Version Checker",
                "4) Exploit DB Search",
                "5) Web Security Headers",
                "6) Config Compliance Check",
                "7) Full Vulnerability Scan",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._cve_lookup, "2": self._ssl_tls_analyzer,
                "3": self._software_version_check, "4": self._exploit_search,
                "5": self._web_security_headers, "6": self._config_compliance,
                "7": self._full_vuln_scan,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")
                    self.config.logger.error(f"Vuln error: {e}", exc_info=True)

    def _cve_lookup(self):
        UI.print_section("CVE Lookup")
        cve_id = UI.ask_input("Enter CVE ID (e.g., CVE-2024-1234)")
        if not cve_id:
            return
        cve_id = cve_id.strip().upper()
        if not InputValidator.validate_cve(cve_id):
            UI.print_error("Invalid CVE ID format (expected CVE-YYYY-NNNNN)")
            return

        try:
            with console.status("Querying NVD..."):
                data = self.threat_intel.nvd_cve_lookup(cve_id)
        except ValueError as e:
            UI.print_warning(f"API note: {e}")
            UI.print_info("NVD API works without a key but with rate limits")
            try:
                with console.status("Querying NVD (no key)..."):
                    data = self.threat_intel.nvd_cve_lookup(cve_id)
            except Exception as e2:
                UI.print_error(f"NVD lookup failed: {e2}")
                return
        except Exception as e:
            UI.print_error(f"NVD lookup failed: {e}")
            return

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            UI.print_warning(f"No data found for {cve_id}")
            return

        cve_data = vulns[0].get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "N/A")

        metrics = cve_data.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])
        cvss_score = "N/A"
        cvss_severity = "N/A"
        if cvss_v31:
            cvss_data = cvss_v31[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", "N/A")
            cvss_severity = cvss_data.get("baseSeverity", "N/A")

        info = {
            "CVE ID": cve_id,
            "Description": desc[:200],
            "CVSS Score": cvss_score,
            "Severity": cvss_severity,
            "Published": cve_data.get("published", "N/A")[:10],
            "Modified": cve_data.get("lastModified", "N/A")[:10],
        }
        UI.print_key_value(info, f"CVE Details: {cve_id}")
        self.config.save_session_history("cve_lookup", f"{cve_id}: CVSS {cvss_score}")

    def _ssl_tls_analyzer(self):
        UI.print_section("SSL/TLS Analyzer")
        target = UI.ask_input("Target hostname (e.g., example.com)")
        if not target:
            return
        target = target.strip()
        port_str = UI.ask_input("Port (default: 443)") or "443"
        try:
            port = int(port_str.strip())
        except ValueError:
            port = 443

        UI.print_info(f"Analyzing SSL/TLS for {target}:{port}...")
        results = {"target": target, "port": port, "issues": []}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    results["protocol"] = version
                    results["cipher"] = cipher[0] if cipher else "N/A"
                    results["bits"] = cipher[2] if cipher and len(cipher) > 2 else "N/A"

                    # Certificate info
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    results["subject_cn"] = subject.get("commonName", "N/A")
                    results["issuer"] = issuer.get("organizationName", "N/A")
                    results["not_before"] = cert.get("notBefore", "N/A")
                    results["not_after"] = cert.get("notAfter", "N/A")
                    results["san"] = [v for _, v in cert.get("subjectAltName", [])]

                    # Check expiry
                    try:
                        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (not_after - datetime.now(timezone.utc).replace(tzinfo=None)).days
                        results["days_until_expiry"] = days_left
                        if days_left < 0:
                            results["issues"].append({"severity": Severity.CRITICAL,
                                                       "title": "Certificate expired",
                                                       "details": f"Expired {abs(days_left)} days ago"})
                        elif days_left < 30:
                            results["issues"].append({"severity": Severity.HIGH,
                                                       "title": "Certificate expiring soon",
                                                       "details": f"{days_left} days remaining"})
                    except Exception as e:
                        self.config.logger.warning("SSL certificate expiry parse failed for %s:%s: %s", target, port, e)
                        pass

                    # Protocol version check
                    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        results["issues"].append({
                            "severity": Severity.HIGH,
                            "title": f"Deprecated protocol: {version}",
                            "details": "Upgrade to TLSv1.2 or TLSv1.3",
                        })

            info = {
                "Subject CN": results.get("subject_cn", "N/A"),
                "Issuer": results.get("issuer", "N/A"),
                "Protocol": results.get("protocol", "N/A"),
                "Cipher": results.get("cipher", "N/A"),
                "Key Bits": results.get("bits", "N/A"),
                "Valid Until": results.get("not_after", "N/A"),
                "Days Until Expiry": results.get("days_until_expiry", "N/A"),
                "SANs": ", ".join(results.get("san", [])[:5]),
            }
            UI.print_key_value(info, f"SSL/TLS: {target}:{port}")

            if results["issues"]:
                for issue in results["issues"]:
                    UI.print_finding(issue["severity"], issue["title"], issue.get("details", ""))
                    self._add_finding(issue["title"], issue["severity"],
                                      issue.get("details", ""), "", "Vulnerability", "Protect")
            else:
                UI.print_success("No SSL/TLS issues found")

        except ssl.SSLCertVerificationError as e:
            UI.print_finding("HIGH", "SSL Certificate Verification Failed", str(e))
            results["issues"].append({"severity": Severity.HIGH, "title": "Cert verification failed"})
        except Exception as e:
            UI.print_error(f"SSL connection failed: {e}")
            return

        self.exporter.ask_export(results, f"ssl_{target}")

    def _software_version_check(self):
        UI.print_section("Software Version Checker")

        # dpkg packages
        UI.print_subsection("Installed Packages (dpkg)")
        rc, out, _ = self.cmd.run(["dpkg", "-l"], timeout=15)
        packages = []
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("ii"):
                    parts = line.split()
                    if len(parts) >= 3:
                        packages.append({"name": parts[1], "version": parts[2],
                                          "desc": " ".join(parts[3:])[:50]})
            UI.print_info(f"Total installed packages: {len(packages)}")

        # pip packages
        UI.print_subsection("Python Packages (pip)")
        rc, out, _ = self.cmd.run(["pip", "list", "--format=json"], timeout=15)
        pip_packages = []
        if rc == 0:
            try:
                pip_packages = json.loads(out)
                UI.print_info(f"Total pip packages: {len(pip_packages)}")
            except json.JSONDecodeError:
                pass

        # Show top packages with known CVE keywords
        security_pkgs = ["openssl", "openssh", "linux-image", "sudo", "curl",
                         "wget", "python3", "nginx", "apache2", "mysql", "postgresql"]
        sec_installed = [p for p in packages if any(s in p["name"] for s in security_pkgs)]
        if sec_installed:
            rows = [[p["name"], p["version"]] for p in sec_installed[:20]]
            UI.print_table("Security-Relevant Packages",
                           [("Package", "cyan"), ("Version", "yellow")], rows)

    def _exploit_search(self):
        UI.print_section("Exploit DB Search")
        query = UI.ask_input("Search term (e.g., CVE ID or software name)")
        if not query:
            return

        # Try searchsploit
        if self.cmd.has_command("searchsploit"):
            UI.print_info("Searching local Exploit-DB...")
            rc, out, _ = self.cmd.run(["searchsploit", "--json", query.strip()], timeout=30)
            if rc == 0:
                try:
                    data = json.loads(out)
                    exploits = data.get("RESULTS_EXPLOIT", [])
                    if exploits:
                        rows = [[e.get("Title", "")[:60], e.get("Path", "")[:40],
                                 e.get("Date_Published", "")] for e in exploits[:20]]
                        UI.print_table(f"Exploits for: {query}",
                                       [("Title", "white"), ("Path", "cyan"), ("Date", "dim")],
                                       rows)
                    else:
                        UI.print_warning("No exploits found in local database")
                except json.JSONDecodeError:
                    console.print(out[:2000])
        else:
            UI.print_warning("searchsploit not installed. Install with: sudo apt install exploitdb")

    def _web_security_headers(self):
        UI.print_section("Web Security Headers Check")
        url = UI.ask_input("Target URL (e.g., https://example.com)")
        if not url:
            return
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            with console.status("Checking headers..."):
                resp = requests.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                                     headers={"User-Agent": USER_AGENT})
        except Exception as e:
            UI.print_error(f"Request failed: {e}")
            return

        headers = dict(resp.headers)
        results = []

        for header in SECURITY_HEADERS:
            present = header in headers or header.lower() in {h.lower() for h in headers}
            value = headers.get(header, "Missing")
            results.append({
                "header": header,
                "value": value[:80] if value != "Missing" else "Missing",
                "status": "PASS" if present else "FAIL",
            })

        # Cookie security
        cookies = resp.headers.get("Set-Cookie", "")
        if cookies:
            if "secure" not in cookies.lower():
                results.append({"header": "Cookie Secure Flag", "value": "Missing", "status": "FAIL"})
            if "httponly" not in cookies.lower():
                results.append({"header": "Cookie HttpOnly Flag", "value": "Missing", "status": "FAIL"})

        for r in results:
            UI.print_check(r["status"], r["header"],
                           r["value"] if r["status"] == "FAIL" else "")
            if r["status"] == "FAIL":
                self._add_finding(f"Missing header: {r['header']}", "MEDIUM",
                                  f"Security header {r['header']} is not set",
                                  f"Add {r['header']} header to responses", "Vulnerability", "Protect")

        passed = sum(1 for r in results if r["status"] == "PASS")
        score = RiskScorer.score_compliance(passed, len(results))
        UI.print_score_panel(score["score"], score["grade"], "Web Headers Score")
        self.exporter.ask_export(results, f"headers_{urlparse(url).netloc}",
                                 rows=results)

    def _config_compliance(self):
        UI.print_section("Configuration Compliance")
        UI.print_info("Running CIS Benchmark checks...")
        results = self.compliance.run_cis_checks()
        passed = sum(1 for r in results if r["status"] == "PASS")
        total = len(results)
        score = RiskScorer.score_compliance(passed, total)

        for r in results:
            UI.print_check(r["status"], f"[{r['id']}] {r['title']}", r.get("details", ""))

        UI.print_score_panel(score["score"], score["grade"], "CIS Compliance Score")
        self.scores["cis"] = score

        html = HTMLReportGenerator.compliance_report(results, "CIS Benchmark", score)
        self.exporter.ask_export(
            {"results": results, "score": score},
            "cis_compliance",
            rows=results, html=html,
        )

    def _full_vuln_scan(self):
        UI.print_section("Full Vulnerability Scan")
        target = UI.ask_input("Target hostname or URL")
        if not target:
            return
        target = target.strip()
        host = target.split("://")[-1].split("/")[0].split(":")[0]

        all_vulns = []
        phase = 0

        # Phase 1: Port Scan
        phase += 1
        UI.print_info(f"Phase {phase}/7: Port Scan...")
        self._full_vuln_port_scan(host, all_vulns)

        # Phase 2: SSL/TLS Analysis
        phase += 1
        UI.print_info(f"Phase {phase}/7: SSL/TLS Analysis...")
        if InputValidator.validate_domain(host) or "." in host:
            self._ssl_tls_analyzer_auto(host, all_vulns)

        # Phase 3: Web Security Headers
        phase += 1
        UI.print_info(f"Phase {phase}/7: Web Security Headers...")
        url = target if target.startswith("http") else f"https://{host}"
        self._web_headers_auto(url, all_vulns)

        # Phase 4: Software Version Check
        phase += 1
        UI.print_info(f"Phase {phase}/7: Software Version Check...")
        self._software_version_check()

        # Phase 5: Configuration Compliance (CIS)
        phase += 1
        UI.print_info(f"Phase {phase}/7: Configuration Compliance...")
        self._full_vuln_config_compliance(all_vulns)

        # Phase 6: Exploit Search (for found CVEs)
        phase += 1
        UI.print_info(f"Phase {phase}/7: Exploit Search...")
        self._full_vuln_exploit_search(all_vulns)

        # Phase 7: Service Vulnerability Check
        phase += 1
        UI.print_info(f"Phase {phase}/7: Service Vulnerability Check...")
        self._full_vuln_service_check(host, all_vulns)

        # Summary
        console.print()
        UI.print_subsection(f"Scan Summary: {target}")
        severity_counts = {}
        for v in all_vulns:
            sev = v.get("severity", Severity.INFO)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in severity_counts:
                color = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow",
                         "LOW": "blue", "INFO": "dim"}.get(sev, "white")
                console.print(f"  [{color}]{sev}: {severity_counts[sev]}[/{color}]")
        UI.print_info(f"Total vulnerabilities found: {len(all_vulns)}")

        if all_vulns:
            score = RiskScorer.score_host(all_vulns)
            UI.print_score_panel(score["score"], score["grade"], "Vulnerability Score")
            for v in all_vulns:
                self._add_finding(
                    v.get("description", "Unknown"), v.get("severity", Severity.MEDIUM),
                    f"{v.get('id', 'N/A')}: {v.get('description', '')}",
                    v.get("recommendation", "Review and remediate"),
                    "Vulnerability", "Detect",
                )
            html = HTMLReportGenerator.vulnerability_report(all_vulns, score)
            self.exporter.ask_export(
                {"vulns": all_vulns, "score": score},
                f"vuln_scan_{host}",
                rows=all_vulns, html=html,
            )
            self.config.save_session_history("full_vuln_scan",
                                             f"{host}: {len(all_vulns)} vulns, score {score['score']}")
        else:
            UI.print_success("No vulnerabilities detected")
            self.config.save_session_history("full_vuln_scan", f"{host}: clean")

    def _full_vuln_port_scan(self, host: str, vulns: list):
        """Quick port scan for common vulnerable ports."""
        risky_ports = {
            21: ("FTP", "Unencrypted file transfer"),
            23: ("Telnet", "Unencrypted remote access"),
            25: ("SMTP", "Open mail relay possible"),
            53: ("DNS", "DNS amplification risk"),
            110: ("POP3", "Unencrypted email"),
            135: ("MSRPC", "Windows RPC exploitation"),
            139: ("NetBIOS", "SMB/NetBIOS information leak"),
            143: ("IMAP", "Unencrypted email"),
            445: ("SMB", "EternalBlue/SMB exploits"),
            1433: ("MSSQL", "Database exposed"),
            1521: ("Oracle", "Database exposed"),
            3306: ("MySQL", "Database exposed"),
            3389: ("RDP", "Remote desktop brute force"),
            5432: ("PostgreSQL", "Database exposed"),
            5900: ("VNC", "Unencrypted remote desktop"),
            6379: ("Redis", "Unauthenticated access possible"),
            8080: ("HTTP-Alt", "Development/proxy server"),
            8443: ("HTTPS-Alt", "Alternative HTTPS"),
            9200: ("Elasticsearch", "Unauthenticated search engine"),
            27017: ("MongoDB", "Unauthenticated database"),
        }
        open_ports = []
        try:
            for port, (service, risk) in risky_ports.items():
                try:
                    with socket.create_connection((host, port), timeout=2):
                        open_ports.append((port, service, risk))
                except (socket.timeout, ConnectionRefusedError, OSError):
                    pass
        except Exception as e:
            self.config.logger.debug("Quick port scan failed for %s: %s", host, e)
            pass

        if open_ports:
            rows = [[str(p), svc, risk] for p, svc, risk in open_ports]
            UI.print_table("Open Risky Ports",
                           [("Port", "red"), ("Service", "cyan"), ("Risk", "yellow")], rows)
            for port, service, risk in open_ports:
                if port in (21, 23, 110, 143, 5900):
                    vulns.append({"id": f"PORT-{port}", "severity": Severity.HIGH,
                                  "description": f"Unencrypted service: {service} on port {port}",
                                  "affected": host, "recommendation": f"Disable or encrypt {service}"})
                elif port in (445, 3389, 6379, 9200, 27017):
                    vulns.append({"id": f"PORT-{port}", "severity": Severity.HIGH,
                                  "description": f"Risky service exposed: {service} on port {port}",
                                  "affected": host, "recommendation": f"Restrict access to {service}"})
                else:
                    vulns.append({"id": f"PORT-{port}", "severity": Severity.MEDIUM,
                                  "description": f"Service exposed: {service} on port {port}",
                                  "affected": host, "recommendation": f"Review {service} configuration"})
        else:
            UI.print_success("No risky ports detected")

    def _full_vuln_config_compliance(self, vulns: list):
        """Run CIS compliance checks as part of full vuln scan."""
        try:
            results = self.compliance.run_cis_checks()
            failed = [r for r in results if r["status"] == "FAIL"]
            passed = sum(1 for r in results if r["status"] == "PASS")
            total = len(results)

            if failed:
                rows = [[r["id"], r["title"], r.get("details", "")[:50]] for r in failed[:15]]
                UI.print_table(f"CIS Failures ({len(failed)}/{total})",
                               [("ID", "red"), ("Check", "white"), ("Details", "dim")], rows)
                for r in failed:
                    sev = "HIGH" if r.get("category") in ("SSH", "Filesystem", "Firewall") else "MEDIUM"
                    vulns.append({"id": f"CIS-{r['id']}", "severity": sev,
                                  "description": f"CIS FAIL: {r['title']}",
                                  "affected": "system", "recommendation": f"Fix CIS {r['id']}: {r['title']}"})
            else:
                UI.print_success(f"All {total} CIS checks passed")

            if total > 0:
                score = RiskScorer.score_compliance(passed, total)
                self.scores["cis_vuln"] = score
        except Exception as e:
            UI.print_warning(f"CIS checks skipped: {e}")

    def _full_vuln_exploit_search(self, vulns: list):
        """Search for exploits matching found vulnerabilities."""
        if not self.cmd.has_command("searchsploit"):
            UI.print_warning("searchsploit not installed — exploit check skipped")
            return

        # Gather unique software from vulns
        search_terms = set()
        for v in vulns:
            desc = v.get("description", "")
            if "service" in desc.lower() or "exposed" in desc.lower():
                # Extract service name
                parts = desc.split(":")
                if len(parts) > 1:
                    svc = parts[0].split()[-1] if parts[0].split() else ""
                    if svc and len(svc) > 2:
                        search_terms.add(svc.lower())

        if not search_terms:
            UI.print_info("No software targets for exploit search")
            return

        total_exploits = 0
        for term in list(search_terms)[:5]:
            try:
                rc, out, _ = self.cmd.run(["searchsploit", "--json", term], timeout=15)
                if rc == 0:
                    data = json.loads(out)
                    exploits = data.get("RESULTS_EXPLOIT", [])
                    if exploits:
                        total_exploits += len(exploits)
                        for e in exploits[:3]:
                            vulns.append({"id": f"EXPLOIT-{term[:8].upper()}",
                                          "severity": Severity.HIGH,
                                          "description": f"Known exploit: {e.get('Title', '')[:60]}",
                                          "affected": term,
                                          "recommendation": "Patch or mitigate vulnerable software"})
            except (json.JSONDecodeError, Exception):
                pass

        if total_exploits:
            UI.print_warning(f"Found {total_exploits} potential exploits")
        else:
            UI.print_success("No known exploits found for detected services")

    def _full_vuln_service_check(self, host: str, vulns: list):
        """Check running services for known vulnerable configurations."""
        checks = [
            (["ss", "-tlnp"], "listening services"),
        ]
        try:
            rc, out, _ = self.cmd.run(["ss", "-tlnp"], timeout=10)
            if rc == 0:
                lines = out.strip().splitlines()[1:]  # skip header
                services_found = len(lines)
                UI.print_info(f"Found {services_found} listening services")

                # Flag services on 0.0.0.0 (all interfaces)
                wide_open = []
                for line in lines:
                    parts = line.split()
                    local = parts[3] if len(parts) > 3 else ""
                    if local.startswith("0.0.0.0:") or local.startswith(":::") or local.startswith("*:"):
                        wide_open.append(local)

                if wide_open:
                    rows = [[addr] for addr in wide_open[:15]]
                    UI.print_table("Services on all interfaces (0.0.0.0)",
                                   [("Address", "yellow")], rows)
                    for addr in wide_open:
                        vulns.append({"id": "SVC-BIND-ALL", "severity": Severity.MEDIUM,
                                      "description": f"Service bound to all interfaces: {addr}",
                                      "affected": host,
                                      "recommendation": "Bind service to specific interface"})
                else:
                    UI.print_success("No services bound to all interfaces")
            else:
                UI.print_warning("Could not check listening services")
        except Exception as e:
            UI.print_warning(f"Service check skipped: {e}")

    def _ssl_tls_analyzer_auto(self, target: str, vulns: list):
        """Automated SSL check for full vuln scan."""
        try:
            context = ssl.create_default_context()
            host = target.split(":")[0]
            with socket.create_connection((host, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        vulns.append({"id": "SSL-001", "severity": Severity.HIGH,
                                      "description": f"Deprecated TLS: {version}",
                                      "affected": target})
                    try:
                        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days = (not_after - datetime.now(timezone.utc).replace(tzinfo=None)).days
                        if days < 0:
                            vulns.append({"id": "SSL-002", "severity": Severity.CRITICAL,
                                          "description": "Expired certificate", "affected": target})
                        elif days < 30:
                            vulns.append({"id": "SSL-003", "severity": Severity.HIGH,
                                          "description": f"Certificate expires in {days} days",
                                          "affected": target})
                    except Exception as e:
                        self.config.logger.warning("SSL auto-analysis certificate parse failed for %s: %s", target, e)
                        pass
        except ssl.SSLCertVerificationError:
            vulns.append({"id": "SSL-004", "severity": Severity.HIGH,
                          "description": "Certificate verification failed", "affected": target})
        except Exception as e:
            self.config.logger.debug("SSL auto-analysis failed for %s: %s", target, e)
            pass

    def _web_headers_auto(self, url: str, vulns: list):
        """Automated header check for full vuln scan."""
        try:
            resp = requests.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                                 headers={"User-Agent": USER_AGENT})
            headers = {h.lower() for h in resp.headers}
            for h in ["strict-transport-security", "content-security-policy",
                       "x-content-type-options", "x-frame-options"]:
                if h not in headers:
                    vulns.append({"id": f"HDR-{h[:6].upper()}", "severity": Severity.MEDIUM,
                                  "description": f"Missing: {h}", "affected": url})
        except Exception as e:
            self.config.logger.debug("Web headers fetch failed for %s: %s", url, e)
            pass

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 4: MONITORING & SIEM
    # ═══════════════════════════════════════════════════════════════════

    def _monitoring_menu(self):
        while True:
            choice = UI.ask_menu("Monitoring & SIEM", [
                "1) Log Analyzer",
                "2) File Integrity Monitor",
                "3) Process Monitor",
                "4) Network Connection Tracker",
                "5) Failed Login Tracker",
                "6) Alert Configuration",
                "7) Incident Timeline Builder",
                "8) Real-Time Dashboard",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._log_analyzer, "2": self._file_integrity_monitor,
                "3": self._process_monitor, "4": self._connection_tracker,
                "5": self._failed_login_tracker, "6": self._alert_configuration,
                "7": self._incident_timeline, "8": self._realtime_dashboard,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")
                    self.config.logger.error(f"Monitoring error: {e}", exc_info=True)

    def _log_analyzer(self):
        UI.print_section("Log Analyzer")
        log_files = {
            "auth.log": "/var/log/auth.log",
            "syslog": "/var/log/syslog",
            "kern.log": "/var/log/kern.log",
        }

        choice = UI.ask_menu("Select log file:", list(log_files.keys()) + ["Custom path", "Back"])
        if not choice or choice == "Back":
            return

        if choice == "Custom path":
            path = UI.ask_input("Log file path")
            if not path:
                return
            log_path = Path(path.strip())
        else:
            log_path = Path(log_files[choice])

        if not log_path.exists():
            UI.print_error(f"File not found: {log_path}")
            return

        try:
            lines = log_path.read_text(errors="replace").splitlines()[-MAX_LOG_LINES:]
        except PermissionError:
            UI.print_error(f"Permission denied: {log_path}")
            return

        events = []
        error_pattern = re.compile(r"(error|fail|denied|refused|invalid|attack|blocked)", re.IGNORECASE)
        critical_pattern = re.compile(r"(segfault|panic|oom-killer|CRITICAL|ALERT)", re.IGNORECASE)

        for line in lines:
            severity = "INFO"
            if critical_pattern.search(line):
                severity = "CRITICAL"
            elif error_pattern.search(line):
                severity = "HIGH"

            if severity != "INFO":
                ts_match = re.match(r"^(\w+\s+\d+\s+[\d:]+)", line)
                timestamp = ts_match.group(1) if ts_match else ""
                events.append({
                    "timestamp": timestamp,
                    "source": log_path.name,
                    "severity": severity,
                    "message": line[:200],
                })

        UI.print_info(f"Analyzed {len(lines)} lines, found {len(events)} notable events")
        UI.print_log_events(events[-50:], f"Events from {log_path.name}")

        if events:
            self.exporter.ask_export(events, f"log_analysis_{log_path.stem}",
                                     rows=events)

    def _file_integrity_monitor(self):
        UI.print_section("File Integrity Monitor")

        choice = UI.ask_menu("FIM Action:", [
            "Create new baseline",
            "Compare against baseline",
            "List baselines",
            "Back",
        ])
        if not choice or choice == "Back":
            return

        if choice.startswith("Create"):
            dirs_input = UI.ask_input("Directories to monitor (comma-separated, e.g., /etc,/usr/bin)")
            if not dirs_input:
                return
            dirs = [d.strip() for d in dirs_input.split(",") if d.strip()]
            name = UI.ask_input("Baseline name (default: 'default')") or "default"

            with console.status("Creating baseline..."):
                baseline = self.baseline_mgr.create_baseline(dirs, name)

            fp = self.baseline_mgr.save_baseline(baseline, name)
            UI.print_success(f"Baseline created: {len(baseline.get('files', {}))} files tracked")
            UI.print_info(f"Saved to: {fp}")

        elif choice.startswith("Compare"):
            baselines = self.baseline_mgr.list_baselines()
            if not baselines:
                UI.print_warning("No baselines found. Create one first.")
                return
            name = UI.ask_menu("Select baseline:", baselines + ["Back"])
            if not name or name == "Back":
                return

            baseline = self.baseline_mgr.load_baseline(name)
            if not baseline:
                UI.print_error("Failed to load baseline")
                return

            with console.status("Comparing with baseline..."):
                diff = self.baseline_mgr.compare_baseline(baseline)

            UI.print_subsection(f"Baseline: {name} ({baseline.get('timestamp', 'N/A')})")
            UI.print_info(f"Baseline files: {diff['total_baseline']}")
            UI.print_info(f"Current files: {diff['total_current']}")

            if diff["added"]:
                UI.print_warning(f"New files: {len(diff['added'])}")
                for f in diff["added"][:20]:
                    UI.print_info(f"  + {f}")

            if diff["removed"]:
                UI.print_warning(f"Removed files: {len(diff['removed'])}")
                for f in diff["removed"][:20]:
                    UI.print_info(f"  - {f}")

            if diff["modified"]:
                UI.print_finding("HIGH", f"Modified files: {len(diff['modified'])}")
                for f in diff["modified"][:20]:
                    UI.print_info(f"  ~ {f}")
                    self._add_finding(f"File modified: {f}", "HIGH",
                                      "File hash changed since baseline",
                                      "Investigate the change", "Monitoring", "Detect")

            if not diff["added"] and not diff["removed"] and not diff["modified"]:
                UI.print_success("No changes detected since baseline")

            self.exporter.ask_export(diff, f"fim_diff_{name}")

        else:
            baselines = self.baseline_mgr.list_baselines()
            if baselines:
                for b in baselines:
                    bl = self.baseline_mgr.load_baseline(b)
                    ts = bl.get("timestamp", "N/A") if bl else "N/A"
                    files = len(bl.get("files", {})) if bl else 0
                    UI.print_info(f"  {b}: {files} files ({ts})")
            else:
                UI.print_info("No baselines found")

    def _process_monitor(self):
        UI.print_section("Process Monitor")

        if HAS_PSUTIL:
            suspicious = []
            for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent",
                                              "memory_percent", "cmdline", "exe"]):
                try:
                    info = proc.info
                    reasons = []
                    name = (info.get("name") or "").lower()
                    cmdline = " ".join(info.get("cmdline") or []).lower()
                    exe = info.get("exe") or ""

                    # Crypto miners
                    if name in CRYPTO_MINERS or any(m in cmdline for m in CRYPTO_MINERS):
                        reasons.append("Crypto miner")

                    # Process from /tmp
                    if exe.startswith("/tmp") or exe.startswith("/dev/shm"):
                        reasons.append("Running from temp dir")

                    # Deleted binary
                    if exe and "(deleted)" in exe:
                        reasons.append("Deleted binary")

                    # High CPU usage
                    cpu = info.get("cpu_percent", 0) or 0
                    if cpu > 90:
                        reasons.append(f"High CPU: {cpu}%")

                    if reasons:
                        suspicious.append({
                            "pid": info.get("pid"),
                            "user": info.get("username", "?"),
                            "cpu": cpu,
                            "mem": info.get("memory_percent", 0) or 0,
                            "cmd": cmdline[:80] or name,
                            "reason": ", ".join(reasons),
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            UI.print_process_table(suspicious)
            if suspicious:
                for p in suspicious:
                    self._add_finding(f"Suspicious process: PID {p['pid']}", "HIGH",
                                      f"{p['cmd']}: {p['reason']}",
                                      "Investigate the process", "Monitoring", "Detect")
            else:
                UI.print_success("No suspicious processes detected")
        else:
            UI.print_warning("psutil not installed, using ps command")
            rc, out, _ = self.cmd.run(["ps", "auxf"], timeout=10)
            if rc == 0:
                console.print(out[:5000])

    def _connection_tracker(self):
        UI.print_section("Network Connection Tracker")
        self._network_connections()

    def _failed_login_tracker(self):
        UI.print_section("Failed Login Tracker")
        auth_log = Path("/var/log/auth.log")
        if not auth_log.exists():
            UI.print_error("auth.log not found")
            return

        try:
            lines = auth_log.read_text(errors="replace").splitlines()[-MAX_LOG_LINES:]
        except PermissionError:
            UI.print_error("Cannot read auth.log (try sudo)")
            return

        failed_pattern = re.compile(
            r"(\w+\s+\d+\s+[\d:]+).*(?:Failed password|authentication failure).*"
            r"(?:from\s+([\d.]+)|user[=\s]+(\S+))",
            re.IGNORECASE,
        )

        failures: Dict[str, list] = {}
        for line in lines:
            m = failed_pattern.search(line)
            if m:
                ts = m.group(1)
                ip = m.group(2) or "local"
                user = m.group(3) or "unknown"
                key = ip
                failures.setdefault(key, []).append({"timestamp": ts, "user": user})

        if failures:
            rows = []
            for ip, attempts in sorted(failures.items(), key=lambda x: -len(x[1])):
                users = set(a["user"] for a in attempts)
                last = attempts[-1]["timestamp"]
                rows.append([ip, str(len(attempts)), ", ".join(list(users)[:5]), last])
                if len(attempts) >= 5:
                    self._add_finding(
                        f"Brute force from {ip}: {len(attempts)} failures", "HIGH",
                        f"Users targeted: {', '.join(list(users)[:5])}",
                        f"Consider blocking IP: sudo ufw deny from {ip}", "Monitoring", "Detect",
                    )

            UI.print_table("Failed Login Attempts",
                           [("Source IP", "cyan"), ("Attempts", "red"), ("Users", "yellow"),
                            ("Last Attempt", "dim")],
                           rows[:30])

            total = sum(len(v) for v in failures.values())
            UI.print_info(f"Total failed attempts: {total} from {len(failures)} source(s)")
        else:
            UI.print_success("No failed login attempts found in recent logs")

    def _alert_configuration(self):
        UI.print_section("Alert Configuration")
        choice = UI.ask_menu("Alert setup:", [
            "Configure Email (SMTP)",
            "Configure Webhook (Slack/Discord)",
            "Test alert",
            "View configuration",
            "Back",
        ])
        if not choice or choice == "Back":
            return

        if choice.startswith("Configure Email"):
            server = UI.ask_input("SMTP server (e.g., smtp.gmail.com)")
            port = UI.ask_input("SMTP port (e.g., 587)") or "587"
            username = UI.ask_input("Username/email")
            password = UI.ask_input("Password (app password recommended)")
            from_addr = username
            to_addr = UI.ask_input("Recipient email")
            if all([server, username, password, to_addr]):
                self.alert_mgr.configure_email(server, int(port), username, password,
                                                from_addr, to_addr)
                UI.print_success("Email alerts configured")

        elif choice.startswith("Configure Webhook"):
            url = UI.ask_input("Webhook URL")
            name = UI.ask_input("Name (e.g., slack, discord)") or "default"
            if url and InputValidator.validate_url(url):
                self.alert_mgr.configure_webhook(url, name)
                UI.print_success(f"Webhook '{name}' configured")
            else:
                UI.print_error("Invalid URL")

        elif choice.startswith("Test"):
            if self.alert_mgr.is_configured():
                self.alert_mgr.send_alert("Test Alert", "This is a test from CyberGuard.", "INFO")
                UI.print_success("Test alert sent")
            else:
                UI.print_warning("No alerts configured")

        else:
            UI.print_key_value({
                "Email": "Configured" if self.alert_mgr.alerts_config.get("email", {}).get("enabled") else "Not configured",
                "Webhooks": str(len(self.alert_mgr.alerts_config.get("webhooks", {}))),
            }, "Alert Configuration")

    def _incident_timeline(self):
        UI.print_section("Incident Timeline Builder")
        events = []

        # Auth log events
        auth_log = Path("/var/log/auth.log")
        if auth_log.exists():
            try:
                for line in auth_log.read_text(errors="replace").splitlines()[-2000:]:
                    ts_match = re.match(r"^(\w+\s+\d+\s+[\d:]+)", line)
                    if ts_match:
                        severity = "INFO"
                        if re.search(r"(failed|denied|error)", line, re.IGNORECASE):
                            severity = "HIGH"
                        elif re.search(r"(accepted|opened|session)", line, re.IGNORECASE):
                            severity = "LOW"
                        if severity != "INFO":
                            events.append({
                                "timestamp": ts_match.group(1),
                                "source": "auth.log",
                                "severity": severity,
                                "message": line[len(ts_match.group(1)):].strip()[:100],
                            })
            except PermissionError:
                UI.print_warning("Cannot read auth.log")

        # syslog events
        syslog = Path("/var/log/syslog")
        if syslog.exists():
            try:
                for line in syslog.read_text(errors="replace").splitlines()[-2000:]:
                    if re.search(r"(error|warning|critical|alert)", line, re.IGNORECASE):
                        ts_match = re.match(r"^(\w+\s+\d+\s+[\d:]+)", line)
                        if ts_match:
                            events.append({
                                "timestamp": ts_match.group(1),
                                "source": "syslog",
                                "severity": Severity.MEDIUM,
                                "message": line[len(ts_match.group(1)):].strip()[:100],
                            })
            except PermissionError:
                pass

        events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        UI.print_log_events(events[:100], "Incident Timeline")
        if events:
            self.exporter.ask_export(events, "incident_timeline", rows=events)

    def _realtime_dashboard(self):
        UI.print_section("Real-Time Dashboard")
        UI.print_info("Starting dashboard (Ctrl+C to stop)...")
        console.print()

        try:
            while True:
                table = Table(title=f"System Status — {datetime.now().strftime('%H:%M:%S')}",
                              box=box.ROUNDED, border_style="bright_blue")
                table.add_column("Metric", style="bold cyan")
                table.add_column("Value", style="white")

                # CPU
                if HAS_PSUTIL:
                    cpu = psutil.cpu_percent(interval=1)
                    mem = psutil.virtual_memory()
                    disk = psutil.disk_usage("/")
                    table.add_row("CPU Usage", f"{cpu}%")
                    table.add_row("Memory", f"{mem.percent}% ({self._human_bytes(mem.used)}/{self._human_bytes(mem.total)})")
                    table.add_row("Disk /", f"{disk.percent}% ({self._human_bytes(disk.used)}/{self._human_bytes(disk.total)})")

                # Network connections
                rc, out, _ = self.cmd.run(["ss", "-s"], timeout=5)
                if rc == 0:
                    for line in out.splitlines():
                        if "TCP:" in line:
                            table.add_row("TCP Sockets", line.split("TCP:")[1].strip()[:60])
                            break

                # Load average
                rc, out, _ = self.cmd.run(["uptime"], timeout=5)
                if rc == 0:
                    load_match = re.search(r"load average:\s*(.*)", out)
                    if load_match:
                        table.add_row("Load Average", load_match.group(1))

                console.clear()
                UI.show_banner()
                console.print(table)
                console.print("\n  [dim]Press Ctrl+C to stop[/dim]")
                time.sleep(4)

        except KeyboardInterrupt:
            console.print("\n  [dim]Dashboard stopped[/dim]")

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 5: THREAT INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════

    def _threat_intel_menu(self):
        while True:
            choice = UI.ask_menu("Threat Intelligence", [
                "1) IP Reputation (VirusTotal)",
                "2) IP Abuse Check (AbuseIPDB)",
                "3) Hash/File Reputation (VirusTotal)",
                "4) WHOIS Intelligence",
                "5) MITRE ATT&CK Mapper",
                "6) IoC Manager",
                "7) Bulk IP Reputation",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._ip_reputation, "2": self._ip_abuse_check,
                "3": self._hash_reputation, "4": self._whois_intelligence,
                "5": self._mitre_attack_mapper, "6": self._ioc_manager,
                "7": self._bulk_ip_reputation,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")
                    self.config.logger.error(f"TI error: {e}", exc_info=True)

    def _ip_reputation(self):
        UI.print_section("IP Reputation — VirusTotal")
        if not self.config.has_api_key("virustotal"):
            UI.print_error("VirusTotal API key not configured. Set in Settings.")
            return
        ip = UI.ask_input("Enter IP address")
        if not ip or not InputValidator.validate_ip(ip.strip()):
            UI.print_error("Invalid IP address")
            return
        ip = ip.strip()

        try:
            with console.status("Querying VirusTotal..."):
                data = self.threat_intel.vt_ip_reputation(ip)
            UI.print_threat_intel(data, "virustotal")
            self.config.save_session_history("ip_reputation", f"VT: {ip}")
            self.exporter.ask_export(data, f"vt_ip_{ip}")
        except Exception as e:
            UI.print_error(f"VirusTotal query failed: {e}")

    def _ip_abuse_check(self):
        UI.print_section("IP Abuse Check — AbuseIPDB")
        if not self.config.has_api_key("abuseipdb"):
            UI.print_error("AbuseIPDB API key not configured. Set in Settings.")
            return
        ip = UI.ask_input("Enter IP address")
        if not ip or not InputValidator.validate_ip(ip.strip()):
            UI.print_error("Invalid IP address")
            return
        ip = ip.strip()

        try:
            with console.status("Querying AbuseIPDB..."):
                data = self.threat_intel.abuseipdb_check(ip)
            UI.print_threat_intel(data, "abuseipdb")

            abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
            if abuse_score >= 75:
                self._add_finding(f"High abuse score for {ip}: {abuse_score}%", "HIGH",
                                  f"AbuseIPDB confidence: {abuse_score}%",
                                  f"Consider blocking {ip}", "Threat Intel", "Detect")
            self.exporter.ask_export(data, f"abuse_{ip}")
        except Exception as e:
            UI.print_error(f"AbuseIPDB query failed: {e}")

    def _hash_reputation(self):
        UI.print_section("Hash/File Reputation — VirusTotal")
        if not self.config.has_api_key("virustotal"):
            UI.print_error("VirusTotal API key not configured. Set in Settings.")
            return
        hash_input = UI.ask_input("Enter file hash (MD5/SHA1/SHA256)")
        if not hash_input:
            return
        hash_input = hash_input.strip()
        hash_type = InputValidator.validate_hash(hash_input)
        if not hash_type:
            UI.print_error("Invalid hash format")
            return

        try:
            with console.status("Querying VirusTotal..."):
                data = self.threat_intel.vt_hash_reputation(hash_input)
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            info = {
                "Hash": hash_input,
                "Type": hash_type.upper(),
                "Name": attrs.get("meaningful_name", "N/A"),
                "Type Description": attrs.get("type_description", "N/A"),
                "Size": f"{attrs.get('size', 0)} bytes",
                "Malicious": stats.get("malicious", 0),
                "Suspicious": stats.get("suspicious", 0),
                "Harmless": stats.get("harmless", 0),
                "Undetected": stats.get("undetected", 0),
            }
            UI.print_key_value(info, "File Reputation")

            if stats.get("malicious", 0) > 0:
                self._add_finding(f"Malicious file detected: {hash_input[:16]}...", "CRITICAL",
                                  f"{stats['malicious']} detections",
                                  "Quarantine the file immediately", "Threat Intel", "Detect")
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 404:
                UI.print_info("Hash not found in VirusTotal database")
            else:
                UI.print_error(f"Query failed: {e}")
        except Exception as e:
            UI.print_error(f"Query failed: {e}")

    def _whois_intelligence(self):
        UI.print_section("WHOIS Intelligence")
        target = UI.ask_input("Enter domain or IP")
        if not target:
            return
        target = target.strip()

        if self.cmd.has_command("whois"):
            with console.status("Running WHOIS lookup..."):
                rc, out, _ = self.cmd.run(["whois", target], timeout=30)
            if rc == 0:
                console.print(Panel(out[:3000], title=f"WHOIS: {target}",
                                    border_style="bright_blue"))
                self.exporter.ask_export({"target": target, "whois": out},
                                         f"whois_{target}",
                                         txt=out)
            else:
                UI.print_error("WHOIS lookup failed")
        else:
            UI.print_error("whois command not found. Install with: sudo apt install whois")

    def _mitre_attack_mapper(self):
        UI.print_section("MITRE ATT&CK Technique Mapper")

        choice = UI.ask_menu("Action:", [
            "Search by technique ID",
            "Search by keyword",
            "Browse all techniques",
            "Map findings to ATT&CK",
            "Back",
        ])
        if not choice or choice == "Back":
            return

        if choice.startswith("Search by technique"):
            tid = UI.ask_input("Technique ID (e.g., T1059)")
            if tid:
                tid = tid.strip().upper()
                matches = {k: v for k, v in MITRE_TECHNIQUES.items()
                           if k.startswith(tid)}
                if matches:
                    rows = [[k, v["name"], v["tactic"]] for k, v in matches.items()]
                    UI.print_table("MITRE ATT&CK Techniques",
                                   [("ID", "cyan"), ("Name", "white"), ("Tactic", "yellow")],
                                   rows)
                else:
                    UI.print_warning("No matching techniques found")

        elif choice.startswith("Search by keyword"):
            kw = UI.ask_input("Keyword")
            if kw:
                kw_lower = kw.strip().lower()
                matches = {k: v for k, v in MITRE_TECHNIQUES.items()
                           if kw_lower in v["name"].lower() or kw_lower in v["tactic"].lower()}
                if matches:
                    rows = [[k, v["name"], v["tactic"]] for k, v in matches.items()]
                    UI.print_table("Matching Techniques",
                                   [("ID", "cyan"), ("Name", "white"), ("Tactic", "yellow")],
                                   rows)
                else:
                    UI.print_warning("No matches found")

        elif choice.startswith("Browse"):
            rows = [[k, v["name"], v["tactic"]] for k, v in MITRE_TECHNIQUES.items()]
            UI.print_table("MITRE ATT&CK Techniques",
                           [("ID", "cyan"), ("Name", "white"), ("Tactic", "yellow")],
                           rows)

        elif choice.startswith("Map findings"):
            if not self.findings:
                UI.print_warning("No findings to map. Run some assessments first.")
                return
            mapped = []
            for f in self.findings:
                techniques = []
                title_lower = f.get("title", "").lower()
                if "brute" in title_lower or "login" in title_lower:
                    techniques.append("T1110")
                if "ssh" in title_lower:
                    techniques.append("T1021.004")
                if "suid" in title_lower or "permission" in title_lower:
                    techniques.append("T1548")
                if "service" in title_lower:
                    techniques.append("T1543")
                if "cron" in title_lower:
                    techniques.append("T1053.003")
                if techniques:
                    mapped.append({"finding": f["title"], "techniques": techniques})

            if mapped:
                rows = [[m["finding"][:50], ", ".join(m["techniques"])] for m in mapped]
                UI.print_table("Findings → ATT&CK Mapping",
                               [("Finding", "white"), ("Techniques", "cyan")], rows)
            else:
                UI.print_info("No findings could be mapped to ATT&CK techniques")

    def _ioc_manager(self):
        UI.print_section("Indicator of Compromise (IoC) Manager")

        choice = UI.ask_menu("IoC Action:", [
            "Add IoC",
            "Search IoCs",
            "List all IoCs",
            "Import from file",
            "Export IoCs",
            "Back",
        ])
        if not choice or choice == "Back":
            return

        iocs = self._load_iocs()

        if choice.startswith("Add"):
            ioc_type = UI.ask_menu("IoC type:", ["ip", "domain", "hash", "url", "email", "cve"])
            if not ioc_type:
                return
            value = UI.ask_input(f"Enter {ioc_type} value")
            if not value:
                return
            description = UI.ask_input("Description (optional)") or ""
            ioc = {
                "type": ioc_type, "value": value.strip(),
                "description": description,
                "added": datetime.now().isoformat(),
                "source": "manual",
            }
            iocs.append(ioc)
            self._save_iocs(iocs)
            UI.print_success(f"IoC added: {ioc_type} = {value.strip()}")

        elif choice.startswith("Search"):
            query = UI.ask_input("Search term")
            if query:
                matches = [i for i in iocs if query.strip().lower() in
                           f"{i['value']} {i.get('description', '')}".lower()]
                if matches:
                    rows = [[i["type"], i["value"][:40], i.get("description", "")[:30],
                             i.get("added", "")[:10]] for i in matches]
                    UI.print_table("Matching IoCs",
                                   [("Type", "cyan"), ("Value", "white"),
                                    ("Description", "dim"), ("Added", "dim")],
                                   rows)
                else:
                    UI.print_warning("No matching IoCs found")

        elif choice.startswith("List"):
            if iocs:
                rows = [[i["type"], i["value"][:40], i.get("description", "")[:30],
                         i.get("added", "")[:10]] for i in iocs[-50:]]
                UI.print_table(f"IoC Database ({len(iocs)} total)",
                               [("Type", "cyan"), ("Value", "white"),
                                ("Description", "dim"), ("Added", "dim")],
                               rows)
            else:
                UI.print_info("IoC database is empty")

        elif choice.startswith("Import"):
            path = UI.ask_input("JSON file path")
            if path:
                try:
                    new_iocs = json.loads(Path(path.strip()).read_text(encoding="utf-8"))
                    if isinstance(new_iocs, list):
                        iocs.extend(new_iocs)
                        self._save_iocs(iocs)
                        UI.print_success(f"Imported {len(new_iocs)} IoCs")
                except Exception as e:
                    UI.print_error(f"Import failed: {e}")

        elif choice.startswith("Export"):
            self.exporter.export_json(iocs, "iocs_export")
            UI.print_success("IoCs exported")

    def _load_iocs(self) -> list:
        if IOCS_FILE.exists():
            try:
                return json.loads(IOCS_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save_iocs(self, iocs: list):
        IOCS_FILE.write_text(json.dumps(iocs, indent=2), encoding="utf-8")

    def _bulk_ip_reputation(self):
        UI.print_section("Bulk IP Reputation Check")
        if not self.config.has_api_key("virustotal") and not self.config.has_api_key("abuseipdb"):
            UI.print_error("No API keys configured for VT or AbuseIPDB")
            return

        ip_input = UI.ask_input("Enter IPs (comma-separated) or file path")
        if not ip_input:
            return

        ips = []
        if Path(ip_input.strip()).exists():
            try:
                content = Path(ip_input.strip()).read_text(encoding="utf-8")
                ips = [l.strip() for l in content.splitlines() if l.strip()]
            except OSError:
                UI.print_error("Cannot read file")
                return
        else:
            ips = [ip.strip() for ip in ip_input.split(",")]

        ips = [ip for ip in ips if InputValidator.validate_ip(ip)]
        if not ips:
            UI.print_error("No valid IPs provided")
            return
        if len(ips) > MAX_BULK_IPS:
            UI.print_warning(f"Limiting to {MAX_BULK_IPS} IPs")
            ips = ips[:MAX_BULK_IPS]

        results = []
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                       BarColumn(), TextColumn("{task.percentage:>3.0f}%")) as progress:
            task = progress.add_task("Checking IPs", total=len(ips))
            for ip in ips:
                result = {"ip": ip, "vt_malicious": "N/A", "abuse_score": "N/A"}
                if self.config.has_api_key("virustotal"):
                    try:
                        data = self.threat_intel.vt_ip_reputation(ip)
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        result["vt_malicious"] = stats.get("malicious", 0)
                    except Exception as e:
                        self.config.logger.debug("VirusTotal enrichment failed for %s: %s", ip, e)
                        pass
                if self.config.has_api_key("abuseipdb"):
                    try:
                        data = self.threat_intel.abuseipdb_check(ip)
                        result["abuse_score"] = data.get("data", {}).get("abuseConfidenceScore", 0)
                    except Exception as e:
                        self.config.logger.debug("AbuseIPDB enrichment failed for %s: %s", ip, e)
                        pass
                results.append(result)
                progress.advance(task)

        rows = [[r["ip"], str(r["vt_malicious"]), f"{r['abuse_score']}%"
                 if r["abuse_score"] != "N/A" else "N/A"] for r in results]
        UI.print_table("Bulk IP Reputation Results",
                       [("IP", "cyan"), ("VT Malicious", "red"), ("Abuse Score", "yellow")],
                       rows)
        self.exporter.ask_export(results, "bulk_ip_reputation", rows=results)

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 6: FORENSICS & INCIDENT RESPONSE
    # ═══════════════════════════════════════════════════════════════════

    def _forensics_menu(self):
        while True:
            choice = UI.ask_menu("Forensics & Incident Response", [
                "1) Memory Info Collector",
                "2) Disk Forensics Helper",
                "3) Timeline Analyzer",
                "4) Evidence Collector",
                "5) Malware Analysis Helper",
                "6) Log Correlator",
                "7) Volatile Data Capture",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._memory_info, "2": self._disk_forensics,
                "3": self._timeline_analyzer, "4": self._evidence_collector_menu,
                "5": self._malware_analysis, "6": self._log_correlator,
                "7": self._volatile_data_capture,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")
                    self.config.logger.error(f"Forensics error: {e}", exc_info=True)

    def _memory_info(self):
        UI.print_section("Memory Info Collector")

        # /proc/meminfo
        content = self.cmd.read_proc_file("/proc/meminfo")
        if content:
            info = {}
            for line in content.splitlines()[:15]:
                parts = line.split(":")
                if len(parts) == 2:
                    info[parts[0].strip()] = parts[1].strip()
            UI.print_key_value(info, "Memory Information")

        if HAS_PSUTIL:
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            UI.print_key_value({
                "Total RAM": self._human_bytes(mem.total),
                "Available": self._human_bytes(mem.available),
                "Used": f"{self._human_bytes(mem.used)} ({mem.percent}%)",
                "Swap Used": f"{self._human_bytes(swap.used)} ({swap.percent}%)",
            }, "Memory Usage")

        # Top memory consumers
        if HAS_PSUTIL:
            procs = []
            for p in psutil.process_iter(["pid", "name", "memory_percent", "memory_info"]):
                try:
                    info = p.info
                    if (info.get("memory_percent") or 0) > 1:
                        procs.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            procs.sort(key=lambda x: x.get("memory_percent", 0), reverse=True)
            rows = [[str(p["pid"]), p.get("name", "?"),
                      f"{p.get('memory_percent', 0):.1f}%",
                      self._human_bytes(p.get("memory_info", None).rss if p.get("memory_info") else 0)]
                     for p in procs[:15]]
            UI.print_table("Top Memory Consumers",
                           [("PID", "bold"), ("Process", "cyan"), ("MEM%", "yellow"), ("RSS", "white")],
                           rows)

    def _disk_forensics(self):
        UI.print_section("Disk Forensics Helper")

        # lsblk
        UI.print_subsection("Block Devices")
        rc, out, _ = self.cmd.run(["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"], timeout=10)
        if rc == 0:
            console.print(f"\n{out}")

        # Recently modified files in sensitive dirs
        UI.print_subsection("Recently Modified Files (last 24h)")
        rc, out, _ = self.cmd.run(
            ["find", "/etc", "/var/log", "/tmp", "-maxdepth", "2", "-type", "f",
             "-mmin", "-1440", "-not", "-name", "*.journal"],
            timeout=30,
        )
        if rc == 0:
            recent = [f.strip() for f in out.splitlines() if f.strip()]
            if recent:
                UI.print_info(f"Found {len(recent)} recently modified files")
                for f in recent[:30]:
                    UI.print_info(f"  {f}")
            else:
                UI.print_info("No recently modified files found")

        # Large files in tmp
        UI.print_subsection("Large Files in /tmp")
        rc, out, _ = self.cmd.run(
            ["find", "/tmp", "-maxdepth", "2", "-type", "f", "-size", "+10M"],
            timeout=15,
        )
        if rc == 0:
            large = [f.strip() for f in out.splitlines() if f.strip()]
            if large:
                UI.print_warning(f"Large files in /tmp: {len(large)}")
                for f in large[:10]:
                    try:
                        size = Path(f).stat().st_size
                        UI.print_info(f"  {f} ({self._human_bytes(size)})")
                    except OSError:
                        UI.print_info(f"  {f}")
            else:
                UI.print_info("No large files in /tmp")

    def _timeline_analyzer(self):
        UI.print_section("Timeline Analyzer")
        UI.print_info("Building forensic timeline from filesystem and logs...")

        events = []

        # Recent file modifications in /etc
        rc, out, _ = self.cmd.run(
            ["find", "/etc", "-maxdepth", "2", "-type", "f", "-mmin", "-4320",
             "-printf", "%T+ %p\n"],
            timeout=30,
        )
        if rc == 0:
            for line in out.splitlines():
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    events.append({
                        "timestamp": parts[0][:19],
                        "source": "filesystem",
                        "severity": Severity.MEDIUM,
                        "message": f"Modified: {parts[1]}",
                    })

        # Auth log events
        auth_log = Path("/var/log/auth.log")
        if auth_log.exists():
            try:
                for line in auth_log.read_text(errors="replace").splitlines()[-1000:]:
                    ts_match = re.match(r"^(\w+\s+\d+\s+[\d:]+)", line)
                    if ts_match and re.search(r"(session|login|sudo|su|failed|accepted)", line, re.IGNORECASE):
                        events.append({
                            "timestamp": ts_match.group(1),
                            "source": "auth.log",
                            "severity": Severity.INFO if "accepted" in line.lower() else "HIGH",
                            "message": line[len(ts_match.group(1)):].strip()[:100],
                        })
            except PermissionError:
                pass

        events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        UI.print_log_events(events[:80], "Forensic Timeline")
        if events:
            self.exporter.ask_export(events, "forensic_timeline", rows=events)

    def _evidence_collector_menu(self):
        UI.print_section("Evidence Collector")
        case_name = UI.ask_input("Case name/identifier")
        if not case_name:
            return
        examiner = UI.ask_input("Examiner name (default: CyberGuard)") or "CyberGuard"

        choice = UI.ask_menu("Collect:", [
            "Specific files",
            "Log files",
            "Config files (/etc)",
            "Back",
        ])
        if not choice or choice == "Back":
            return

        files = []
        if choice.startswith("Specific"):
            paths = UI.ask_input("File paths (comma-separated)")
            if paths:
                files = [p.strip() for p in paths.split(",") if p.strip()]
        elif choice.startswith("Log"):
            log_dir = Path("/var/log")
            if log_dir.exists():
                files = [str(f) for f in log_dir.glob("*.log")][:20]
                files.extend([str(f) for f in log_dir.glob("auth*")][:5])
        elif choice.startswith("Config"):
            config_files = [
                "/etc/passwd", "/etc/shadow", "/etc/group",
                "/etc/ssh/sshd_config", "/etc/hosts", "/etc/resolv.conf",
                "/etc/crontab", "/etc/fstab", "/etc/sudoers",
            ]
            files = [f for f in config_files if Path(f).exists()]

        if not files:
            UI.print_warning("No files to collect")
            return

        UI.print_info(f"Collecting {len(files)} file(s)...")
        with console.status("Packaging evidence..."):
            manifest = self.evidence.collect_files(files, case_name, examiner)

        collected = sum(1 for f in manifest.get("files", []) if f.get("status") == "COLLECTED")
        UI.print_success(f"Evidence collected: {collected}/{len(files)} files")
        UI.print_info(f"Archive: {manifest.get('archive', 'N/A')}")
        UI.print_info(f"SHA-256: {manifest.get('archive_sha256', 'N/A')}")

    def _malware_analysis(self):
        UI.print_section("Malware Analysis Helper")
        filepath = UI.ask_input("File path to analyze")
        if not filepath:
            return
        fp = Path(filepath.strip())
        if not fp.exists():
            UI.print_error("File not found")
            return

        results = {"file": str(fp), "analyses": {}}

        # file command
        if self.cmd.has_command("file"):
            rc, out, _ = self.cmd.run(["file", str(fp)], timeout=10)
            if rc == 0:
                results["analyses"]["file_type"] = out.strip()
                UI.print_info(f"Type: {out.strip()}")

        # File hash
        h = BaselineManager.hash_file(fp)
        if h:
            results["analyses"]["sha256"] = h
            UI.print_info(f"SHA-256: {h}")

        md5 = hashlib.md5()
        try:
            with open(fp, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
            results["analyses"]["md5"] = md5.hexdigest()
            UI.print_info(f"MD5: {md5.hexdigest()}")
        except Exception as e:
            self.config.logger.warning("MD5 hash calculation failed for %s: %s", fp, e)
            pass

        # strings (first 50)
        if self.cmd.has_command("strings"):
            rc, out, _ = self.cmd.run(["strings", "-n", "8", str(fp)], timeout=15)
            if rc == 0:
                strings = out.splitlines()[:50]
                results["analyses"]["strings_count"] = len(out.splitlines())
                suspicious_strings = [s for s in strings if any(
                    kw in s.lower() for kw in ["/etc/passwd", "/bin/sh", "socket",
                                                 "connect", "exec", "system", "wget",
                                                 "curl", "chmod", "base64"])]
                if suspicious_strings:
                    UI.print_subsection("Suspicious Strings")
                    for s in suspicious_strings[:20]:
                        UI.print_warning(f"  {s}")

        # Shared libraries (using objdump -p, NOT ldd which executes the binary)
        if self.cmd.has_command("objdump"):
            rc, out, _ = self.cmd.run(["objdump", "-p", str(fp)], timeout=10)
            if rc == 0:
                needed_libs = [
                    line.strip() for line in out.splitlines()
                    if "NEEDED" in line
                ]
                if needed_libs:
                    UI.print_subsection("Shared Libraries (objdump -p)")
                    for lib in needed_libs[:50]:
                        console.print(f"  {lib}")

        # VirusTotal hash lookup
        if h and self.config.has_api_key("virustotal"):
            if UI.confirm("Check hash on VirusTotal?"):
                try:
                    with console.status("Querying VirusTotal..."):
                        data = self.threat_intel.vt_hash_reputation(h)
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    UI.print_key_value({
                        "Malicious": stats.get("malicious", 0),
                        "Suspicious": stats.get("suspicious", 0),
                        "Harmless": stats.get("harmless", 0),
                    }, "VirusTotal Results")
                except Exception as e:
                    UI.print_warning(f"VT lookup failed: {e}")

        self.exporter.ask_export(results, f"malware_analysis_{fp.name}")

    def _log_correlator(self):
        UI.print_section("Log Correlator")
        UI.print_info("Cross-referencing auth.log + syslog + connections...")

        events = []

        # Auth events
        auth_log = Path("/var/log/auth.log")
        if auth_log.exists():
            try:
                for line in auth_log.read_text(errors="replace").splitlines()[-3000:]:
                    if re.search(r"(failed|accepted|sudo|su\[|session)", line, re.IGNORECASE):
                        ts_match = re.match(r"^(\w+\s+\d+\s+[\d:]+)", line)
                        if ts_match:
                            events.append({
                                "timestamp": ts_match.group(1),
                                "source": "auth",
                                "severity": Severity.HIGH if "failed" in line.lower() else "INFO",
                                "message": line[len(ts_match.group(1)):].strip()[:120],
                            })
            except PermissionError:
                UI.print_warning("Cannot read auth.log")

        # Syslog events
        syslog = Path("/var/log/syslog")
        if syslog.exists():
            try:
                for line in syslog.read_text(errors="replace").splitlines()[-3000:]:
                    if re.search(r"(error|warning|kernel|UFW)", line, re.IGNORECASE):
                        ts_match = re.match(r"^(\w+\s+\d+\s+[\d:]+)", line)
                        if ts_match:
                            events.append({
                                "timestamp": ts_match.group(1),
                                "source": "syslog",
                                "severity": Severity.MEDIUM,
                                "message": line[len(ts_match.group(1)):].strip()[:120],
                            })
            except PermissionError:
                pass

        # Current connections
        rc, out, _ = self.cmd.run(["ss", "-tunap"], timeout=10)
        if rc == 0:
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5 and "ESTAB" in line:
                    events.append({
                        "timestamp": datetime.now().strftime("%b %d %H:%M:%S"),
                        "source": "network",
                        "severity": Severity.INFO,
                        "message": f"Active: {parts[3]} → {parts[4]}",
                    })

        events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        UI.print_log_events(events[:100], "Correlated Events")
        UI.print_info(f"Total events: {len(events)} (auth: {sum(1 for e in events if e['source']=='auth')}, "
                      f"syslog: {sum(1 for e in events if e['source']=='syslog')}, "
                      f"network: {sum(1 for e in events if e['source']=='network')})")
        if events:
            self.exporter.ask_export(events, "log_correlation", rows=events)

    def _volatile_data_capture(self):
        UI.print_section("Volatile Data Capture")
        UI.print_info("Capturing volatile system state...")

        case_name = UI.ask_input("Case name (default: volatile)") or "volatile"
        with console.status("Capturing volatile data..."):
            data = self.evidence.capture_volatile_data(case_name)

        for section, info in data.get("sections", {}).items():
            rc = info.get("return_code", -1)
            output = info.get("output", "")
            status = "[green]OK[/green]" if rc == 0 else "[red]FAIL[/red]"
            console.print(f"  {status} {section}: {len(output)} bytes")

        fp = self.exporter.export_json(data, f"volatile_{case_name}")
        UI.print_success(f"Volatile data saved: {fp}")

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 7: REPORTING & COMPLIANCE
    # ═══════════════════════════════════════════════════════════════════

    def _reporting_menu(self):
        while True:
            choice = UI.ask_menu("Reporting & Compliance", [
                "1) Security Assessment Report",
                "2) NIST CSF Compliance",
                "3) CIS Benchmark (Ubuntu)",
                "4) Executive Summary",
                "5) Risk Scoring Dashboard",
                "6) Remediation Tracker",
                "7) Export All Reports",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._security_assessment_report, "2": self._nist_csf_compliance,
                "3": self._cis_benchmark, "4": self._executive_summary_report,
                "5": self._risk_scoring_dashboard, "6": self._remediation_tracker_menu,
                "7": self._export_all_reports,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")
                    self.config.logger.error(f"Reporting error: {e}", exc_info=True)

    def _security_assessment_report(self):
        UI.print_section("Security Assessment Report")
        if not self.findings:
            UI.print_warning("No findings yet. Run some assessments first.")
            return

        UI.print_info(f"Total findings: {len(self.findings)}")
        severity_counts = {}
        for f in self.findings:
            s = f.get("severity", Severity.LOW)
            severity_counts[s] = severity_counts.get(s, 0) + 1
        UI.print_key_value(severity_counts, "Findings by Severity")

        for f in self.findings:
            UI.print_finding(f["severity"], f["title"], f.get("description", ""))

        html = HTMLReportGenerator.assessment_report(self.findings, self.scores)
        self.exporter.ask_export(
            {"findings": self.findings, "scores": self.scores},
            "security_assessment",
            rows=self.findings, html=html,
        )

    def _nist_csf_compliance(self):
        UI.print_section("NIST CSF Compliance Assessment")

        if not self.findings:
            UI.print_info("Running quick hardening check to generate findings...")
            self._os_security_audit()
            self._kernel_params()
            self._ssh_hardening()

        nist = self.compliance.nist_csf_assessment(self.findings)

        for func_name, func_data in nist.items():
            score = func_data["score"]
            grade = RiskScorer._grade(score)
            UI.print_subsection(f"{func_name}: {score}/100 (Grade {grade})")
            items = func_data.get("items", [])
            if items:
                for item in items[:5]:
                    UI.print_finding(item["severity"], item["title"])

        overall = RiskScorer.aggregate([{"score": v["score"]} for v in nist.values()])
        UI.print_score_panel(overall["score"], overall["grade"], "NIST CSF Overall Score")
        self.scores["nist_csf"] = overall

        nist_results = [{"id": k, "title": k, "status": "PASS" if v["score"] >= 70 else "FAIL",
                          "details": f"Score: {v['score']}"} for k, v in nist.items()]
        html = HTMLReportGenerator.compliance_report(nist_results, "NIST CSF", overall)
        self.exporter.ask_export({"nist": nist, "overall": overall},
                                  "nist_csf_compliance", html=html)

    def _cis_benchmark(self):
        UI.print_section("CIS Benchmark — Ubuntu")
        UI.print_info("Running automated CIS checks...")

        with console.status("Running CIS checks..."):
            results = self.compliance.run_cis_checks()

        passed = sum(1 for r in results if r["status"] == "PASS")
        total = len(results)
        score = RiskScorer.score_compliance(passed, total)

        # Group by category
        by_cat = {}
        for r in results:
            cat = r.get("category", "Other")
            by_cat.setdefault(cat, []).append(r)

        for cat, items in by_cat.items():
            p = sum(1 for i in items if i["status"] == "PASS")
            UI.print_subsection(f"{cat}: {p}/{len(items)} passed")
            for i in items:
                UI.print_check(i["status"], f"[{i['id']}] {i['title']}", i.get("details", ""))

        UI.print_score_panel(score["score"], score["grade"], "CIS Compliance Score")
        self.scores["cis"] = score
        self.config.save_score("cis", score["score"])

        html = HTMLReportGenerator.compliance_report(results, "CIS Benchmark (Ubuntu)", score)
        self.exporter.ask_export(
            {"results": results, "score": score},
            "cis_benchmark",
            rows=results, html=html,
        )

    def _executive_summary_report(self):
        UI.print_section("Executive Summary")
        if not self.findings and not self.scores:
            UI.print_warning("No data available. Run assessments first.")
            return

        summary = ExecutiveSummary.generate(self.findings, self.scores)
        UI.print_score_panel(summary["score"], summary["grade"], "Overall Security Grade")
        UI.print_key_value(summary["severity_counts"], "Findings by Severity")

        if summary["recommendations"]:
            UI.print_subsection("Key Recommendations")
            for i, r in enumerate(summary["recommendations"][:10], 1):
                console.print(f"  {i}. {r}")

        html = HTMLReportGenerator.executive_summary(
            summary["grade"], summary["score"], summary["total_findings"],
            summary["top_findings"], summary["recommendations"],
        )
        self.exporter.ask_export(summary, "executive_summary", html=html)

    def _risk_scoring_dashboard(self):
        UI.print_section("Risk Scoring Dashboard")

        if self.scores:
            UI.print_subsection("Current Session Scores")
            rows = [[cat, str(s.get("score", 0)), s.get("grade", "N/A")]
                    for cat, s in self.scores.items()]
            UI.print_table("Security Scores",
                           [("Category", "cyan"), ("Score", "white"), ("Grade", "yellow")],
                           rows)
            overall = RiskScorer.aggregate(list(self.scores.values()))
            UI.print_score_panel(overall["score"], overall["grade"], "Overall Score")
        else:
            UI.print_warning("No scores in current session")

        # Historical scores
        history = self.config.get_scores(limit=20)
        if history:
            UI.print_subsection("Historical Scores")
            rows = [[h.get("timestamp", "")[:16], h.get("category", ""),
                      str(h.get("score", 0))] for h in history[-10:]]
            UI.print_table("Score History",
                           [("Date", "dim"), ("Category", "cyan"), ("Score", "white")],
                           rows)

    def _remediation_tracker_menu(self):
        UI.print_section("Remediation Tracker")
        choice = UI.ask_menu("Remediation:", [
            "View open items",
            "View all items",
            "Update item status",
            "Add from current findings",
            "Statistics",
            "Back",
        ])
        if not choice or choice == "Back":
            return

        if choice.startswith("View open"):
            items = self.remediation.get_open()
            UI.print_remediation_table(items)

        elif choice.startswith("View all"):
            items = self.remediation.get_all()
            UI.print_remediation_table(items)

        elif choice.startswith("Update"):
            items = self.remediation.get_open()
            if not items:
                UI.print_info("No open items")
                return
            UI.print_remediation_table(items)
            item_id = UI.ask_input("Item ID to update")
            if not item_id:
                return
            try:
                item_id = int(item_id.strip())
            except ValueError:
                UI.print_error("Invalid ID")
                return
            new_status = UI.ask_menu("New status:", ["in-progress", "resolved", "Back"])
            if not new_status or new_status == "Back":
                return
            note = UI.ask_input("Note (optional)") or ""
            if self.remediation.update_status(item_id, new_status, note):
                UI.print_success(f"Item #{item_id} updated to '{new_status}'")
            else:
                UI.print_error("Item not found")

        elif choice.startswith("Add from"):
            high_findings = [f for f in self.findings if f.get("severity") in ("CRITICAL", "HIGH")]
            if not high_findings:
                UI.print_info("No critical/high findings to add")
                return
            self.remediation.add_from_findings(high_findings)
            UI.print_success(f"Added {len(high_findings)} findings to remediation tracker")

        elif choice.startswith("Statistics"):
            stats = self.remediation.get_stats()
            UI.print_key_value(stats, "Remediation Statistics")

    def _export_all_reports(self):
        UI.print_section("Export All Reports")
        UI.print_info(f"Creating archive of session results...")

        archive_name = f"cyberguard_session_{self.config.session_id}"
        archive_path = self.config.results_dir / f"{archive_name}.tar.gz"

        with tarfile.open(archive_path, "w:gz") as tar:
            for f in self.config.results_dir.glob("*"):
                if f.name != archive_path.name and f.is_file():
                    tar.add(f, arcname=f.name)

        UI.print_success(f"Archive created: {archive_path}")
        UI.print_info(f"Size: {self._human_bytes(archive_path.stat().st_size)}")

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 8: AUTOMATED WORKFLOWS
    # ═══════════════════════════════════════════════════════════════════

    def _workflows_menu(self):
        while True:
            choice = UI.ask_menu("Automated Workflows", [
                "1) Quick Security Audit (~5 min)",
                "2) Full Security Assessment (~15 min)",
                "3) Incident Response Snapshot (~3 min)",
                "4) Pre-Deployment Check (~5 min)",
                "5) Monthly Security Review (~20 min)",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._workflow_quick_audit,
                "2": self._workflow_full_assessment,
                "3": self._workflow_ir_snapshot,
                "4": self._workflow_pre_deployment,
                "5": self._workflow_monthly_review,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Workflow error: {e}")
                    self.config.logger.error(f"Workflow error: {e}", exc_info=True)

    def _workflow_quick_audit(self):
        UI.print_section("Quick Security Audit")
        phases = [
            ("Phase 1/5: OS Security", self._os_security_audit),
            ("Phase 2/5: Open Ports (local)", lambda: self._quick_local_ports()),
            ("Phase 3/5: Failed Logins", self._failed_login_tracker),
            ("Phase 4/5: SUID Files", self._file_permission_audit),
            ("Phase 5/5: Network Connections", self._network_connections),
        ]
        self._run_workflow_phases(phases)
        self._workflow_summary("Quick Security Audit")

    def _workflow_full_assessment(self):
        UI.print_section("Full Security Assessment")
        phases = [
            ("Phase 1/8: OS Security", self._os_security_audit),
            ("Phase 2/8: Kernel Parameters", self._kernel_params),
            ("Phase 3/8: SSH Hardening", self._ssh_hardening),
            ("Phase 4/8: Service Audit", self._service_hardening),
            ("Phase 5/8: File Permissions", self._file_permission_audit),
            ("Phase 6/8: User Security", self._user_pam_security),
            ("Phase 7/8: Failed Logins", self._failed_login_tracker),
            ("Phase 8/8: CIS Benchmark", lambda: self.compliance.run_cis_checks()),
        ]
        self._run_workflow_phases(phases)
        self._workflow_summary("Full Security Assessment")

    def _workflow_ir_snapshot(self):
        UI.print_section("Incident Response Snapshot")
        phases = [
            ("Phase 1/5: Volatile Data", lambda: self._volatile_data_capture_auto()),
            ("Phase 2/5: Active Connections", self._network_connections),
            ("Phase 3/5: Process Monitor", self._process_monitor),
            ("Phase 4/5: Failed Logins", self._failed_login_tracker),
            ("Phase 5/5: Log Analysis", lambda: self._log_analyzer_auto()),
        ]
        self._run_workflow_phases(phases)
        self._workflow_summary("Incident Response Snapshot")

    def _workflow_pre_deployment(self):
        UI.print_section("Pre-Deployment Security Check")
        phases = [
            ("Phase 1/6: Firewall Config", self._firewall_config_audit),
            ("Phase 2/6: SSH Hardening", self._ssh_hardening),
            ("Phase 3/6: Service Audit", self._service_hardening),
            ("Phase 4/6: File Permissions", self._file_permission_audit),
            ("Phase 5/6: Kernel Parameters", self._kernel_params),
            ("Phase 6/6: User Security", self._user_pam_security),
        ]
        self._run_workflow_phases(phases)
        self._workflow_summary("Pre-Deployment Check")

    def _workflow_monthly_review(self):
        UI.print_section("Monthly Security Review")
        phases = [
            ("Phase 1/7: Full Hardening", self._full_hardening_report),
            ("Phase 2/7: CIS Benchmark", lambda: self._config_compliance()),
            ("Phase 3/7: Failed Logins", self._failed_login_tracker),
            ("Phase 4/7: Process Monitor", self._process_monitor),
            ("Phase 5/7: Network Connections", self._network_connections),
            ("Phase 6/7: NIST CSF", self._nist_csf_compliance),
            ("Phase 7/7: Executive Summary", self._executive_summary_report),
        ]
        self._run_workflow_phases(phases)
        self._workflow_summary("Monthly Security Review")

    def _run_workflow_phases(self, phases: List[Tuple[str, callable]]):
        start = time.time()
        for name, func in phases:
            console.print(f"\n[bold cyan]>>> {name}[/bold cyan]")
            try:
                func()
            except Exception as e:
                UI.print_error(f"{name} failed: {e}")
                self.config.logger.error(f"Workflow phase failed: {name}: {e}", exc_info=True)
        elapsed = time.time() - start
        UI.print_info(f"Completed in {elapsed:.1f}s")

    def _workflow_summary(self, workflow_name: str):
        """Generate workflow summary."""
        console.print()
        UI.print_section(f"{workflow_name} — Summary")

        if self.findings:
            severity_counts = {}
            for f in self.findings:
                s = f.get("severity", Severity.LOW)
                severity_counts[s] = severity_counts.get(s, 0) + 1
            UI.print_key_value(severity_counts, "Findings by Severity")

        if self.scores:
            overall = RiskScorer.aggregate(list(self.scores.values()))
            UI.print_score_panel(overall["score"], overall["grade"], "Overall Security Score")
            self.config.save_score(workflow_name, overall["score"])

        # Auto-save report
        if self.findings:
            summary = ExecutiveSummary.generate(self.findings, self.scores)
            html = HTMLReportGenerator.executive_summary(
                summary["grade"], summary["score"], summary["total_findings"],
                summary["top_findings"], summary["recommendations"],
            )
            fp = self.exporter.export_html(html, f"workflow_{InputValidator.sanitize_filename(workflow_name)}")
            fp2 = self.exporter.export_json(
                {"findings": self.findings, "scores": self.scores, "summary": summary},
                f"workflow_{InputValidator.sanitize_filename(workflow_name)}_data",
            )
            UI.print_success(f"Report saved: {fp}")
            UI.print_success(f"Data saved: {fp2}")

        self.config.save_session_history(workflow_name, f"{len(self.findings)} findings")

        if self.alert_mgr.is_configured():
            critical = sum(1 for f in self.findings if f.get("severity") == Severity.CRITICAL)
            if critical > 0:
                self.alert_mgr.send_alert(
                    f"{workflow_name}: {critical} CRITICAL findings",
                    f"CyberGuard found {critical} critical issues. Review the report.",
                    "CRITICAL",
                )

    def _quick_local_ports(self):
        """Quick local port check for workflow."""
        rc, out, _ = self.cmd.run(["ss", "-tlnp"], timeout=10)
        if rc == 0:
            services = []
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    services.append(parts[3])
            UI.print_info(f"Listening ports: {len(services)}")
            for s in services[:20]:
                UI.print_info(f"  {s}")

    def _volatile_data_capture_auto(self):
        """Auto volatile capture for workflow."""
        data = self.evidence.capture_volatile_data("ir_workflow")
        fp = self.exporter.export_json(data, "volatile_ir_workflow")
        UI.print_success(f"Volatile data saved: {fp}")

    def _log_analyzer_auto(self):
        """Auto log analysis for workflow."""
        auth_log = Path("/var/log/auth.log")
        if auth_log.exists():
            try:
                lines = auth_log.read_text(errors="replace").splitlines()[-5000:]
                error_count = sum(1 for l in lines if re.search(r"(error|fail|denied)", l, re.IGNORECASE))
                UI.print_info(f"auth.log: {len(lines)} lines analyzed, {error_count} notable events")
            except PermissionError:
                UI.print_warning("Cannot read auth.log")
        syslog = Path("/var/log/syslog")
        if syslog.exists():
            try:
                lines = syslog.read_text(errors="replace").splitlines()[-5000:]
                error_count = sum(1 for l in lines if re.search(r"(error|warning)", l, re.IGNORECASE))
                UI.print_info(f"syslog: {len(lines)} lines analyzed, {error_count} notable events")
            except PermissionError:
                pass

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 9: SETTINGS & CONFIGURATION
    # ═══════════════════════════════════════════════════════════════════

    def _settings_menu(self):
        while True:
            choice = UI.ask_menu("Settings & Configuration", [
                "1) Manage API Keys",
                "2) Alert Configuration",
                "3) Manage Baselines",
                "4) Session History",
                "5) About",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._manage_api_keys,
                "2": self._alert_configuration,
                "3": self._manage_baselines_menu,
                "4": self._session_history,
                "5": self._about,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")

    def _manage_api_keys(self):
        UI.print_section("API Key Management")

        services = {
            "virustotal": "VirusTotal (https://www.virustotal.com/gui/my-apikey)",
            "abuseipdb": "AbuseIPDB (https://www.abuseipdb.com/account/api)",
            "nvd": "NVD (https://nvd.nist.gov/developers/request-an-api-key)",
        }

        current = {}
        for svc, desc in services.items():
            key = self.config.get_api_key(svc)
            current[desc] = f"{'*' * 8}{key[-4:]}" if key else "Not set"
        UI.print_key_value(current, "Current API Keys")

        svc = UI.ask_menu("Configure key for:", list(services.keys()) + ["Back"])
        if not svc or svc == "Back":
            return

        key = UI.ask_input(f"Enter {svc} API key")
        if key and key.strip():
            self.config.save_api_key(svc, key.strip())
            # Reinitialize threat intel
            self.threat_intel = ThreatIntelAPI(self.config)
            UI.print_success(f"{svc} API key saved")

    def _manage_baselines_menu(self):
        UI.print_section("Baseline Management")
        self._file_integrity_monitor()

    def _session_history(self):
        UI.print_section("Session History")
        history = self.config.load_history(limit=30)
        if not history:
            UI.print_info("No session history")
            return
        rows = [[h.get("timestamp", ""), h.get("session", "")[:12],
                 h.get("action", ""), h.get("details", "")[:40]]
                for h in reversed(history)]
        UI.print_table("Recent Session History",
                       [("Timestamp", "dim"), ("Session", "cyan"),
                        ("Action", "yellow"), ("Details", "white")],
                       rows)

    def _about(self):
        UI.print_section("About CyberGuard")
        info = {
            "Version": VERSION,
            "Application": APP_NAME,
            "Config Directory": str(CONFIG_DIR),
            "Results Directory": str(OUTPUT_DIR),
            "Current Session": self.config.session_id,
            "Session Results": str(self.config.results_dir),
            "psutil": "installed" if HAS_PSUTIL else "not installed",
            "dnspython": "installed" if HAS_DNSPYTHON else "not installed",
            "cryptography": "installed" if HAS_CRYPTOGRAPHY else "not installed",
            "API Keys": f"{len(self.config.api_keys)} configured",
            "Findings (session)": len(self.findings),
        }
        UI.print_key_value(info, "System Information")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Entry point for CyberGuard toolkit."""
    try:
        toolkit = CyberGuardToolkit()
        toolkit.run()
    except KeyboardInterrupt:
        console.print("\n[bold cyan]Goodbye! Stay secure.[/bold cyan]\n")
    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {e}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
