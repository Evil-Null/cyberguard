"""Tests for Monitoring & SIEM category handlers."""

import pytest
from unittest.mock import patch, MagicMock, call, PropertyMock

from cyberguard_toolkit import CyberGuardToolkit


class TestLogAnalyzer:
    """Tests for _log_analyzer method."""

    def test_back_choice(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = "Back"
            toolkit._log_analyzer()

    def test_none_choice(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = None
            toolkit._log_analyzer()

    def test_auth_log_not_found(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Path") as mock_path:
            mock_select.return_value.ask.return_value = "auth.log"
            mock_path.return_value.exists.return_value = False
            mock_path.return_value.__str__ = lambda self: "/var/log/auth.log"
            toolkit._log_analyzer()

    def test_auth_log_permission_denied(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Path") as mock_path:
            mock_select.return_value.ask.return_value = "auth.log"
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.read_text.side_effect = PermissionError("denied")
            mock_path.return_value.name = "auth.log"
            mock_path.return_value.__str__ = lambda self: "/var/log/auth.log"
            toolkit._log_analyzer()

    def test_auth_log_success(self, toolkit, sample_auth_log):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Path") as mock_path:
            mock_select.return_value.ask.return_value = "auth.log"
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.read_text.return_value = sample_auth_log
            mock_path.return_value.name = "auth.log"
            mock_path.return_value.stem = "auth"
            mock_path.return_value.__str__ = lambda self: "/var/log/auth.log"
            toolkit._log_analyzer()

    def test_custom_path_empty(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            mock_select.return_value.ask.return_value = "Custom path"
            toolkit._log_analyzer()

    def test_custom_path_success(self, toolkit, tmp_path, sample_auth_log):
        log_file = tmp_path / "custom.log"
        log_file.write_text(sample_auth_log)
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Prompt.ask", return_value=str(log_file)):
            mock_select.return_value.ask.return_value = "Custom path"
            toolkit._log_analyzer()


class TestFileIntegrityMonitor:
    """Tests for _file_integrity_monitor method."""

    def test_back_choice(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = "Back"
            toolkit._file_integrity_monitor()

    def test_create_baseline(self, toolkit, tmp_path):
        etc_dir = tmp_path / "etc"
        etc_dir.mkdir()
        (etc_dir / "test.conf").write_text("config")
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Prompt.ask") as mock_prompt:
            mock_select.return_value.ask.return_value = "Create new baseline"
            mock_prompt.side_effect = [str(etc_dir), "test_bl"]
            toolkit._file_integrity_monitor()

    def test_create_baseline_no_dirs(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            mock_select.return_value.ask.return_value = "Create new baseline"
            toolkit._file_integrity_monitor()

    def test_compare_no_baselines(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch.object(toolkit.baseline_mgr, "list_baselines", return_value=[]):
            mock_select.return_value.ask.return_value = "Compare against baseline"
            toolkit._file_integrity_monitor()

    def test_compare_with_baseline(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch.object(
                 toolkit.baseline_mgr, "list_baselines",
                 return_value=["default"],
             ), \
             patch.object(
                 toolkit.baseline_mgr, "load_baseline",
                 return_value={
                     "timestamp": "2026-01-01",
                     "files": {"/etc/test": "abc123"},
                 },
             ), \
             patch.object(
                 toolkit.baseline_mgr, "compare_baseline",
                 return_value={
                     "total_baseline": 1,
                     "total_current": 1,
                     "added": [],
                     "removed": [],
                     "modified": [],
                 },
             ), \
             patch.object(toolkit.exporter, "ask_export"):
            mock_select.return_value.ask.side_effect = [
                "Compare against baseline",
                "default",
            ]
            toolkit._file_integrity_monitor()

    def test_compare_with_changes(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch.object(
                 toolkit.baseline_mgr, "list_baselines",
                 return_value=["default"],
             ), \
             patch.object(
                 toolkit.baseline_mgr, "load_baseline",
                 return_value={
                     "timestamp": "2026-01-01",
                     "files": {"/etc/test": "abc123"},
                 },
             ), \
             patch.object(
                 toolkit.baseline_mgr, "compare_baseline",
                 return_value={
                     "total_baseline": 3,
                     "total_current": 4,
                     "added": ["/etc/new.conf"],
                     "removed": ["/etc/old.conf"],
                     "modified": ["/etc/test.conf"],
                 },
             ), \
             patch.object(toolkit.exporter, "ask_export"):
            mock_select.return_value.ask.side_effect = [
                "Compare against baseline",
                "default",
            ]
            toolkit._file_integrity_monitor()
        assert any("File modified" in f["title"] for f in toolkit.findings)

    def test_list_baselines(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch.object(
                 toolkit.baseline_mgr, "list_baselines",
                 return_value=["default"],
             ), \
             patch.object(
                 toolkit.baseline_mgr, "load_baseline",
                 return_value={
                     "timestamp": "2026-01-01",
                     "files": {"a": "b"},
                 },
             ):
            mock_select.return_value.ask.return_value = "List baselines"
            toolkit._file_integrity_monitor()

    def test_list_baselines_empty(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch.object(
                 toolkit.baseline_mgr, "list_baselines",
                 return_value=[],
             ):
            mock_select.return_value.ask.return_value = "List baselines"
            toolkit._file_integrity_monitor()


class TestProcessMonitor:
    """Tests for _process_monitor method."""

    def test_with_psutil(self, toolkit, monkeypatch):
        monkeypatch.setattr("cyberguard_toolkit.HAS_PSUTIL", True)
        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 1234,
            "name": "python3",
            "username": "root",
            "cpu_percent": 5.0,
            "memory_percent": 2.0,
            "cmdline": ["app.py"],
            "exe": "/usr/bin/python3",
        }
        with patch("psutil.process_iter", return_value=[mock_proc]):
            toolkit._process_monitor()

    def test_suspicious_process(self, toolkit, monkeypatch):
        monkeypatch.setattr("cyberguard_toolkit.HAS_PSUTIL", True)
        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 9999,
            "name": "xmrig",
            "username": "nobody",
            "cpu_percent": 95.0,
            "memory_percent": 5.0,
            "cmdline": ["--algo=rx"],
            "exe": "/tmp/xmrig",
        }
        with patch("psutil.process_iter", return_value=[mock_proc]):
            toolkit._process_monitor()
        assert any("Suspicious process" in f["title"] for f in toolkit.findings)

    def test_without_psutil(self, toolkit, monkeypatch):
        monkeypatch.setattr("cyberguard_toolkit.HAS_PSUTIL", False)
        with patch.object(
            toolkit.cmd, "run",
            return_value=(0, "PID TTY STAT TIME COMMAND\n", ""),
        ):
            toolkit._process_monitor()

    def test_deleted_binary(self, toolkit, monkeypatch):
        monkeypatch.setattr("cyberguard_toolkit.HAS_PSUTIL", True)
        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 555,
            "name": "evil",
            "username": "root",
            "cpu_percent": 10.0,
            "memory_percent": 5.0,
            "cmdline": [],
            "exe": "/usr/bin/evil (deleted)",
        }
        with patch("psutil.process_iter", return_value=[mock_proc]):
            toolkit._process_monitor()
        assert any("Suspicious" in f["title"] for f in toolkit.findings)


class TestConnectionTracker:
    """Tests for _connection_tracker method."""

    def test_calls_network_connections(self, toolkit):
        with patch.object(toolkit, "_network_connections") as mock_nc:
            toolkit._connection_tracker()
            mock_nc.assert_called_once()


class TestFailedLoginTracker:
    """Tests for _failed_login_tracker method."""

    def test_no_auth_log(self, toolkit):
        with patch("cyberguard_toolkit.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            toolkit._failed_login_tracker()

    def test_permission_denied(self, toolkit):
        with patch("cyberguard_toolkit.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.read_text.side_effect = PermissionError("denied")
            toolkit._failed_login_tracker()

    def test_brute_force_detected(self, toolkit, sample_auth_log):
        with patch("cyberguard_toolkit.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.read_text.return_value = sample_auth_log
            toolkit._failed_login_tracker()
        assert any("Brute force" in f["title"] for f in toolkit.findings)

    def test_no_failures(self, toolkit):
        with patch("cyberguard_toolkit.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.read_text.return_value = (
                "Feb 10 10:00:06 server sshd[1235]: Accepted publickey for user1\n"
            )
            toolkit._failed_login_tracker()
        assert len(toolkit.findings) == 0


class TestAlertConfiguration:
    """Tests for _alert_configuration method."""

    def test_back(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = "Back"
            toolkit._alert_configuration()

    def test_configure_email(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Prompt.ask") as mock_prompt:
            mock_select.return_value.ask.return_value = "Configure Email (SMTP)"
            mock_prompt.side_effect = [
                "smtp.gmail.com", "587", "user@gmail.com",
                "pass123", "admin@co.com",
            ]
            toolkit._alert_configuration()

    def test_configure_webhook(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Prompt.ask") as mock_prompt:
            mock_select.return_value.ask.return_value = "Configure Webhook (Slack/Discord)"
            mock_prompt.side_effect = [
                "https://hooks.slack.com/services/xxx",
                "slack",
            ]
            toolkit._alert_configuration()

    def test_configure_webhook_invalid_url(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Prompt.ask") as mock_prompt:
            mock_select.return_value.ask.return_value = "Configure Webhook (Slack/Discord)"
            mock_prompt.side_effect = ["not-a-url", "test"]
            toolkit._alert_configuration()

    def test_test_alert_configured(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch.object(toolkit.alert_mgr, "is_configured", return_value=True), \
             patch.object(toolkit.alert_mgr, "send_alert"):
            mock_select.return_value.ask.return_value = "Test alert"
            toolkit._alert_configuration()

    def test_test_alert_not_configured(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch.object(toolkit.alert_mgr, "is_configured", return_value=False):
            mock_select.return_value.ask.return_value = "Test alert"
            toolkit._alert_configuration()

    def test_view_configuration(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = "View configuration"
            toolkit._alert_configuration()


class TestIncidentTimeline:
    """Tests for _incident_timeline method."""

    def test_no_logs(self, toolkit):
        with patch("cyberguard_toolkit.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            toolkit._incident_timeline()

    def test_with_auth_log(self, toolkit, sample_auth_log):
        def path_factory(p):
            mock = MagicMock()
            if "auth" in str(p):
                mock.exists.return_value = True
                mock.read_text.return_value = sample_auth_log
            else:
                mock.exists.return_value = False
            return mock

        with patch("cyberguard_toolkit.Path", side_effect=path_factory), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._incident_timeline()


class TestRealtimeDashboard:
    """Tests for _realtime_dashboard method."""

    def test_dashboard_ctrl_c(self, toolkit, monkeypatch):
        monkeypatch.setattr("cyberguard_toolkit.HAS_PSUTIL", False)

        call_count = 0

        def mock_run(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise KeyboardInterrupt
            return (0, "TCP: 0", "")

        with patch.object(toolkit.cmd, "run", side_effect=mock_run), \
             patch("time.sleep", side_effect=KeyboardInterrupt):
            toolkit._realtime_dashboard()
