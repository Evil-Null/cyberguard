"""Shared fixtures for CyberGuard test suite."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from cyberguard_toolkit import (
    Config,
    InputValidator,
    SystemCommandRunner,
    ThreatIntelAPI,
    ResultExporter,
    RiskScorer,
    HTMLReportGenerator,
    BaselineManager,
    AlertManager,
    ComplianceChecker,
    ExecutiveSummary,
    ProgressEstimator,
    UI,
    RemediationTracker,
    EvidenceCollector,
    CyberGuardToolkit,
    VERSION,
    CONFIG_DIR,
    OUTPUT_DIR,
)


# ---------------------------------------------------------------------------
# Directory monkeypatching
# ---------------------------------------------------------------------------

def _monkeypatch_dirs(monkeypatch, tmp_path):
    """Helper to monkeypatch all config directories."""
    monkeypatch.setattr("cyberguard_toolkit.CONFIG_DIR", tmp_path / ".cyberguard")
    monkeypatch.setattr("cyberguard_toolkit.API_KEYS_FILE", tmp_path / ".cyberguard" / "api_keys.json")
    monkeypatch.setattr("cyberguard_toolkit.CONFIG_FILE", tmp_path / ".cyberguard" / "config.json")
    monkeypatch.setattr("cyberguard_toolkit.ALERTS_FILE", tmp_path / ".cyberguard" / "alerts.json")
    monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE", tmp_path / ".cyberguard" / "iocs.json")
    monkeypatch.setattr("cyberguard_toolkit.REMEDIATION_FILE", tmp_path / ".cyberguard" / "remediation.json")
    monkeypatch.setattr("cyberguard_toolkit.SCORES_FILE", tmp_path / ".cyberguard" / "scores.json")
    monkeypatch.setattr("cyberguard_toolkit.HISTORY_FILE", tmp_path / ".cyberguard" / "history.json")
    monkeypatch.setattr("cyberguard_toolkit.BASELINES_DIR", tmp_path / ".cyberguard" / "baselines")
    monkeypatch.setattr("cyberguard_toolkit.EVIDENCE_DIR", tmp_path / ".cyberguard" / "evidence")
    monkeypatch.setattr("cyberguard_toolkit.LOGS_DIR", tmp_path / ".cyberguard" / "logs")
    monkeypatch.setattr("cyberguard_toolkit.QUERIES_DIR", tmp_path / ".cyberguard" / "queries")
    monkeypatch.setattr("cyberguard_toolkit.CACHE_DIR", tmp_path / ".cyberguard" / "cache")
    monkeypatch.setattr("cyberguard_toolkit.OUTPUT_DIR", tmp_path / "results")


# ---------------------------------------------------------------------------
# Core fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_config(tmp_path, monkeypatch):
    """Config with temp directories."""
    _monkeypatch_dirs(monkeypatch, tmp_path)
    return Config()


@pytest.fixture
def mock_logger():
    return MagicMock()


@pytest.fixture
def cmd_runner(mock_logger):
    return SystemCommandRunner(mock_logger)


@pytest.fixture
def exporter(tmp_config):
    return ResultExporter(tmp_config.results_dir, tmp_config.logger)


@pytest.fixture
def threat_intel(tmp_config):
    return ThreatIntelAPI(tmp_config)


@pytest.fixture
def baseline_mgr(mock_logger):
    return BaselineManager(mock_logger)


@pytest.fixture
def alert_mgr(tmp_config):
    return AlertManager(tmp_config)


@pytest.fixture
def compliance_checker(cmd_runner, mock_logger):
    return ComplianceChecker(cmd_runner, mock_logger)


@pytest.fixture
def remediation(mock_logger, tmp_path, monkeypatch):
    monkeypatch.setattr("cyberguard_toolkit.REMEDIATION_FILE", tmp_path / "remediation.json")
    return RemediationTracker(mock_logger)


@pytest.fixture
def evidence(cmd_runner, mock_logger):
    return EvidenceCollector(cmd_runner, mock_logger)


@pytest.fixture
def toolkit(tmp_path, monkeypatch):
    """Full CyberGuardToolkit instance with temp directories."""
    _monkeypatch_dirs(monkeypatch, tmp_path)
    return CyberGuardToolkit()


@pytest.fixture
def toolkit_with_findings(toolkit, sample_findings):
    """Toolkit pre-loaded with findings and scores."""
    toolkit.findings = list(sample_findings)
    toolkit.scores = {
        "hardening": {"score": 65.0, "grade": "D"},
        "ssh": {"score": 42.9, "grade": "F"},
        "kernel": {"score": 80.0, "grade": "B"},
    }
    return toolkit


# ---------------------------------------------------------------------------
# Sample data fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_findings():
    return [
        {"title": "ASLR disabled", "severity": "HIGH",
         "description": "ASLR not enabled", "recommendation": "Enable ASLR",
         "category": "Hardening", "nist_function": "Protect"},
        {"title": "SSH root login", "severity": "HIGH",
         "description": "Root login allowed", "recommendation": "Disable root SSH",
         "category": "Hardening", "nist_function": "Protect"},
        {"title": "World-writable /etc/config", "severity": "CRITICAL",
         "description": "File writable by all", "recommendation": "Fix permissions",
         "category": "Hardening", "nist_function": "Protect"},
        {"title": "Missing HSTS header", "severity": "MEDIUM",
         "description": "No HSTS", "recommendation": "Add HSTS header",
         "category": "Vulnerability", "nist_function": "Protect"},
        {"title": "Port 4444 open", "severity": "HIGH",
         "description": "Suspicious port", "recommendation": "Close port",
         "category": "Network", "nist_function": "Detect"},
    ]


@pytest.fixture
def sample_scores():
    return {
        "hardening": {"score": 65.0, "grade": "D"},
        "ssh": {"score": 42.9, "grade": "F"},
        "kernel": {"score": 80.0, "grade": "B"},
    }


@pytest.fixture
def sample_cis_results():
    return [
        {"id": "1.5.1", "title": "ASLR enabled",
         "category": "Process Hardening", "status": "PASS", "details": "Value: 2"},
        {"id": "5.2.8", "title": "SSH root login disabled",
         "category": "SSH", "status": "FAIL", "details": "PermitRootLogin = yes"},
        {"id": "3.2.8", "title": "TCP SYN Cookies",
         "category": "Network", "status": "PASS", "details": "Value: 1"},
    ]


@pytest.fixture
def mock_cmd_pass():
    """Mock SystemCommandRunner.run that always succeeds."""
    mock = MagicMock()
    mock.return_value = (0, "", "")
    return mock


@pytest.fixture
def mock_cmd_fail():
    """Mock SystemCommandRunner.run that always fails."""
    mock = MagicMock()
    mock.return_value = (1, "", "error")
    return mock


# ---------------------------------------------------------------------------
# Sample output data
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_ss_output():
    return (
        "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
        'LISTEN 0      128    0.0.0.0:22           0.0.0.0:*     users:(("sshd",pid=1234,fd=3))\n'
        'LISTEN 0      128    0.0.0.0:80           0.0.0.0:*     users:(("nginx",pid=2345,fd=6))\n'
        'LISTEN 0      128    127.0.0.1:3306       0.0.0.0:*     users:(("mysqld",pid=3456,fd=10))\n'
        'ESTAB  0      0      192.168.1.5:22       10.0.0.1:54321 users:(("sshd",pid=1235,fd=4))\n'
        'ESTAB  0      0      192.168.1.5:80       10.0.0.2:4444  users:(("nginx",pid=2346,fd=8))\n'
    )


@pytest.fixture
def sample_arp_output():
    return (
        "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
        "192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE\n"
        "192.168.1.3 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
        "10.0.0.1 dev eth0  FAILED\n"
    )


@pytest.fixture
def sample_auth_log():
    return (
        "Feb 10 10:00:01 server sshd[1234]: Failed password for root from 10.0.0.5 user=root\n"
        "Feb 10 10:00:02 server sshd[1234]: Failed password for root from 10.0.0.5 user=root\n"
        "Feb 10 10:00:03 server sshd[1234]: Failed password for root from 10.0.0.5 user=root\n"
        "Feb 10 10:00:04 server sshd[1234]: Failed password for admin from 10.0.0.5 user=admin\n"
        "Feb 10 10:00:05 server sshd[1234]: Failed password for admin from 10.0.0.5 user=admin\n"
        "Feb 10 10:00:06 server sshd[1235]: Accepted publickey for user1 from 192.168.1.100 port 22\n"
        "Feb 10 10:01:00 server sudo[2000]: user1 : TTY=pts/0 ; PWD=/home ; COMMAND=/bin/ls\n"
        "Feb 10 10:02:00 server sshd[1236]: error: PAM: Authentication failure for baduser from 10.0.0.6\n"
        "Feb 10 10:03:00 server kernel: [12345.678] segfault at 0 ip 00007f\n"
    )


@pytest.fixture
def sample_sshd_config():
    return (
        "# sshd_config\n"
        "Port 22\n"
        "PermitRootLogin yes\n"
        "PasswordAuthentication yes\n"
        "PermitEmptyPasswords no\n"
        "X11Forwarding yes\n"
        "MaxAuthTries 6\n"
        "IgnoreRhosts yes\n"
        "HostbasedAuthentication no\n"
        "UsePAM yes\n"
    )


@pytest.fixture
def sample_proc_net_dev():
    return (
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|"
        "bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo: 1234567    1000    0    0    0     0          0         0  "
        "1234567    1000    0    0    0     0       0          0\n"
        "  eth0: 98765432   50000    0    0    0     0          0         0 "
        "45678901   30000    0    0    0     0       0          0\n"
    )


@pytest.fixture
def sample_vt_ip_response():
    return {
        "data": {
            "attributes": {
                "as_owner": "Google LLC",
                "asn": 15169,
                "country": "US",
                "reputation": 0,
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 80,
                    "undetected": 7,
                },
            }
        }
    }


@pytest.fixture
def sample_abuse_response():
    return {
        "data": {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 85,
            "isp": "Evil ISP",
            "countryCode": "RU",
            "domain": "evil.com",
            "totalReports": 42,
            "numDistinctUsers": 15,
            "isWhitelisted": False,
        }
    }
