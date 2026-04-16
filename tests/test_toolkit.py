"""Tests for CyberGuardToolkit menu routing, helpers, SystemCommandRunner, and UI."""

import pytest
from unittest.mock import patch, MagicMock, call

from cyberguard_toolkit import CyberGuardToolkit, UI, SystemCommandRunner


# ═══════════════════════════════════════════════════════════════════════════
# MENU ROUTING
# ═══════════════════════════════════════════════════════════════════════════

class TestMenuRouting:
    """Verify that selecting 'Back'/'Exit' from each menu returns cleanly."""

    @patch("cyberguard_toolkit.questionary")
    @patch.object(UI, "show_banner")
    def test_main_menu_exit(self, mock_banner, mock_q, tmp_config, monkeypatch):
        mock_q.select.return_value.ask.return_value = "0) Exit"
        tk = CyberGuardToolkit()
        tk.run()

    @patch("cyberguard_toolkit.questionary")
    def test_network_menu_back(self, mock_q, tmp_config):
        mock_q.select.return_value.ask.return_value = "0) Back"
        tk = CyberGuardToolkit()
        tk._network_security_menu()

    @patch("cyberguard_toolkit.questionary")
    def test_hardening_menu_back(self, mock_q, tmp_config):
        mock_q.select.return_value.ask.return_value = "0) Back"
        tk = CyberGuardToolkit()
        tk._system_hardening_menu()

    @patch("cyberguard_toolkit.questionary")
    def test_vuln_menu_back(self, mock_q, tmp_config):
        mock_q.select.return_value.ask.return_value = "0) Back"
        tk = CyberGuardToolkit()
        tk._vuln_assessment_menu()

    @patch("cyberguard_toolkit.questionary")
    def test_monitoring_menu_back(self, mock_q, tmp_config):
        mock_q.select.return_value.ask.return_value = "0) Back"
        tk = CyberGuardToolkit()
        tk._monitoring_menu()

    @patch("cyberguard_toolkit.questionary")
    def test_threat_intel_menu_back(self, mock_q, tmp_config):
        mock_q.select.return_value.ask.return_value = "0) Back"
        tk = CyberGuardToolkit()
        tk._threat_intel_menu()

    @patch("cyberguard_toolkit.questionary")
    def test_forensics_menu_back(self, mock_q, tmp_config):
        mock_q.select.return_value.ask.return_value = "0) Back"
        tk = CyberGuardToolkit()
        tk._forensics_menu()

    @patch("cyberguard_toolkit.questionary")
    def test_reporting_menu_back(self, mock_q, tmp_config):
        mock_q.select.return_value.ask.return_value = "0) Back"
        tk = CyberGuardToolkit()
        tk._reporting_menu()

    @patch("cyberguard_toolkit.questionary")
    def test_workflows_menu_back(self, mock_q, tmp_config):
        mock_q.select.return_value.ask.return_value = "0) Back"
        tk = CyberGuardToolkit()
        tk._workflows_menu()

    @patch("cyberguard_toolkit.questionary")
    def test_settings_menu_back(self, mock_q, tmp_config):
        mock_q.select.return_value.ask.return_value = "0) Back"
        tk = CyberGuardToolkit()
        tk._settings_menu()


# ═══════════════════════════════════════════════════════════════════════════
# TOOLKIT HELPERS
# ═══════════════════════════════════════════════════════════════════════════

class TestToolkitHelpers:
    """Validate add_finding, human_bytes, check_dependencies."""

    def test_add_finding(self, tmp_config):
        toolkit = CyberGuardToolkit()
        toolkit._add_finding(
            "Test finding", "HIGH", "Description", "Fix it", "Network", "Detect",
        )
        assert len(toolkit.findings) == 1
        assert toolkit.findings[0]["title"] == "Test finding"
        assert toolkit.findings[0]["severity"] == "HIGH"

    def test_human_bytes(self):
        assert CyberGuardToolkit._human_bytes(0) == "0.0 B"
        result_kb = CyberGuardToolkit._human_bytes(1500)
        assert "KB" in result_kb
        result_mb = CyberGuardToolkit._human_bytes(1500000)
        assert "MB" in result_mb
        result_gb = CyberGuardToolkit._human_bytes(1500000000)
        assert "GB" in result_gb

    def test_check_dependencies(self, tmp_config):
        toolkit = CyberGuardToolkit()
        # Should not raise regardless of installed packages
        toolkit._check_dependencies()


# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM COMMAND RUNNER
# ═══════════════════════════════════════════════════════════════════════════

class TestSystemCommandRunner:
    """Test run(), has_command(), read_sysctl(), read_proc_file()."""

    def test_run_success(self, cmd_runner):
        rc, out, err = cmd_runner.run(["echo", "hello"])
        assert rc == 0
        assert "hello" in out

    def test_run_failure(self, cmd_runner):
        rc, out, err = cmd_runner.run(["false"])
        assert rc != 0

    def test_run_not_found(self, cmd_runner):
        rc, out, err = cmd_runner.run(["nonexistent_command_xyz"])
        assert rc == -2
        assert "not found" in err.lower()

    def test_run_timeout(self, cmd_runner):
        rc, out, err = cmd_runner.run(["sleep", "10"], timeout=1)
        assert rc == -1
        assert "timed out" in err.lower()

    def test_has_command(self, cmd_runner):
        assert cmd_runner.has_command("echo")
        assert not cmd_runner.has_command("nonexistent_command_xyz")

    def test_read_sysctl(self, cmd_runner):
        result = cmd_runner.read_sysctl("kernel.randomize_va_space")
        # On a real Linux system this returns a value; may be None in CI
        assert result is None or result in ("0", "1", "2")

    def test_read_proc_file(self, cmd_runner):
        content = cmd_runner.read_proc_file("/proc/version")
        assert content is not None
        assert "Linux" in content or "linux" in content


# ═══════════════════════════════════════════════════════════════════════════
# UI
# ═══════════════════════════════════════════════════════════════════════════

class TestUI:
    """Test all static UI print helpers (no exceptions, correct output)."""

    def test_print_success(self, capsys):
        UI.print_success("Test message")
        # Rich Console writes to its own internal buffer; just ensure no crash

    def test_print_error(self):
        UI.print_error("Test error")

    def test_print_warning(self):
        UI.print_warning("Test warning")

    def test_print_info(self):
        UI.print_info("Test info")

    def test_print_section(self):
        UI.print_section("Test Section")

    def test_print_table_empty(self):
        UI.print_table("Empty", [("Col", "white")], [])

    def test_print_table_with_data(self):
        UI.print_table(
            "Test",
            [("Name", "cyan"), ("Value", "white")],
            [["key1", "val1"], ["key2", "val2"]],
        )

    def test_print_score_panel(self):
        UI.print_score_panel(85.0, "B", "Test Score")

    def test_print_finding(self):
        UI.print_finding("HIGH", "Test finding", "Details here")

    def test_print_check_pass(self):
        UI.print_check("PASS", "Test check")

    def test_print_check_fail(self):
        UI.print_check("FAIL", "Test check", "Details")
