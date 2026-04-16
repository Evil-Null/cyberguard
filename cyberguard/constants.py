"""CyberGuard constants, enums, and configuration values."""
import ipaddress
import logging
import re
from enum import StrEnum
from pathlib import Path

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
