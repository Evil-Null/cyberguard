"""Tests for Reporting, Workflows, and Settings categories of CyberGuardToolkit."""

import json
import tarfile
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from cyberguard_toolkit import (
    CyberGuardToolkit,
    RiskScorer,
    HTMLReportGenerator,
    ExecutiveSummary,
    InputValidator,
)


# ═══════════════════════════════════════════════════════════════════════════
# REPORTING — Security Assessment Report
# ═══════════════════════════════════════════════════════════════════════════

class TestSecurityAssessmentReport:

    def test_no_findings(self, toolkit):
        toolkit._security_assessment_report()

    def test_with_findings(self, toolkit_with_findings):
        with patch.object(toolkit_with_findings.exporter, "ask_export"):
            toolkit_with_findings._security_assessment_report()


# ═══════════════════════════════════════════════════════════════════════════
# REPORTING — NIST CSF Compliance
# ═══════════════════════════════════════════════════════════════════════════

class TestNISTCSFCompliance:

    def test_with_existing_findings(self, toolkit_with_findings):
        with patch.object(toolkit_with_findings, "_os_security_audit"), \
             patch.object(toolkit_with_findings, "_kernel_params"), \
             patch.object(toolkit_with_findings, "_ssh_hardening"), \
             patch.object(toolkit_with_findings.exporter, "ask_export"):
            toolkit_with_findings._nist_csf_compliance()
            assert "nist_csf" in toolkit_with_findings.scores

    def test_no_findings_runs_checks(self, toolkit):
        with patch.object(toolkit, "_os_security_audit") as mock_os, \
             patch.object(toolkit, "_kernel_params"), \
             patch.object(toolkit, "_ssh_hardening"), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._nist_csf_compliance()
            mock_os.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════
# REPORTING — CIS Benchmark
# ═══════════════════════════════════════════════════════════════════════════

class TestCISBenchmark:

    def test_cis_benchmark(self, toolkit):
        results = [
            {"id": "1.1.1", "title": "cramfs disabled",
             "status": "PASS", "category": "Filesystem", "details": ""},
            {"id": "5.2.8", "title": "SSH root login",
             "status": "FAIL", "category": "SSH",
             "details": "PermitRootLogin=yes"},
        ]
        with patch.object(toolkit.compliance, "run_cis_checks",
                          return_value=results), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._cis_benchmark()
            assert "cis" in toolkit.scores


# ═══════════════════════════════════════════════════════════════════════════
# REPORTING — Executive Summary
# ═══════════════════════════════════════════════════════════════════════════

class TestExecutiveSummaryReport:

    def test_no_data(self, toolkit):
        toolkit._executive_summary_report()

    def test_with_data(self, toolkit_with_findings):
        with patch.object(toolkit_with_findings.exporter, "ask_export"):
            toolkit_with_findings._executive_summary_report()


# ═══════════════════════════════════════════════════════════════════════════
# REPORTING — Risk Scoring Dashboard
# ═══════════════════════════════════════════════════════════════════════════

class TestRiskScoringDashboard:

    def test_no_scores(self, toolkit):
        toolkit._risk_scoring_dashboard()

    def test_with_scores(self, toolkit_with_findings):
        toolkit_with_findings._risk_scoring_dashboard()

    def test_with_history(self, toolkit):
        toolkit.scores = {"test": {"score": 75.0, "grade": "C"}}
        with patch.object(toolkit.config, "get_scores",
                          return_value=[{
                              "timestamp": "2026-02-10T10:00:00",
                              "category": "test",
                              "score": 75.0,
                          }]):
            toolkit._risk_scoring_dashboard()


# ═══════════════════════════════════════════════════════════════════════════
# REPORTING — Remediation Tracker Menu
# ═══════════════════════════════════════════════════════════════════════════

class TestRemediationTrackerMenu:

    def test_back(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "Back"
            toolkit._remediation_tracker_menu()

    def test_view_open(self, toolkit):
        with patch.object(toolkit.remediation, "get_open",
                          return_value=[]), \
             patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "View open items"
            toolkit._remediation_tracker_menu()

    def test_view_all(self, toolkit):
        with patch.object(toolkit.remediation, "get_all",
                          return_value=[]), \
             patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "View all items"
            toolkit._remediation_tracker_menu()

    def test_update_no_items(self, toolkit):
        with patch.object(toolkit.remediation, "get_open",
                          return_value=[]), \
             patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "Update item status"
            toolkit._remediation_tracker_menu()

    def test_update_item(self, toolkit):
        items = [{"id": 1, "title": "Fix SSH",
                  "status": "open", "severity": "HIGH"}]
        with patch.object(toolkit.remediation, "get_open",
                          return_value=items), \
             patch.object(toolkit.remediation, "update_status"), \
             patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask",
                   side_effect=["1", "Fixed it"]):
            mock_sel.return_value.ask.side_effect = [
                "Update item status", "resolved"]
            toolkit._remediation_tracker_menu()

    def test_update_invalid_id(self, toolkit):
        items = [{"id": 1, "title": "Fix SSH",
                  "status": "open", "severity": "HIGH"}]
        with patch.object(toolkit.remediation, "get_open",
                          return_value=items), \
             patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask", return_value="abc"):
            mock_sel.return_value.ask.return_value = "Update item status"
            toolkit._remediation_tracker_menu()

    def test_add_from_findings(self, toolkit_with_findings):
        with patch.object(toolkit_with_findings.remediation,
                          "add_from_findings"), \
             patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = \
                "Add from current findings"
            toolkit_with_findings._remediation_tracker_menu()

    def test_add_from_findings_none(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = \
                "Add from current findings"
            toolkit._remediation_tracker_menu()

    def test_statistics(self, toolkit):
        with patch.object(toolkit.remediation, "get_stats",
                          return_value={
                              "total": 5, "open": 3,
                              "in-progress": 0, "resolved": 0,
                          }), \
             patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "Statistics"
            toolkit._remediation_tracker_menu()


# ═══════════════════════════════════════════════════════════════════════════
# REPORTING — Export All Reports
# ═══════════════════════════════════════════════════════════════════════════

class TestExportAllReports:

    def test_export(self, toolkit, tmp_path):
        results_dir = toolkit.config.results_dir
        results_dir.mkdir(parents=True, exist_ok=True)
        (results_dir / "test_report.json").write_text("{}")
        (results_dir / "test_data.csv").write_text("a,b")
        toolkit._export_all_reports()


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOWS — Run Workflow Phases
# ═══════════════════════════════════════════════════════════════════════════

class TestRunWorkflowPhases:

    def test_all_pass(self, toolkit):
        toolkit._run_workflow_phases([
            ("Phase 1", lambda: None),
            ("Phase 2", lambda: None),
        ])

    def test_phase_fails(self, toolkit):
        def fail_fn():
            raise RuntimeError("boom")

        toolkit._run_workflow_phases([
            ("Phase 1", lambda: None),
            ("Phase 2", fail_fn),
            ("Phase 3", lambda: None),
        ])


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOWS — Workflow Summary
# ═══════════════════════════════════════════════════════════════════════════

class TestWorkflowSummary:

    def test_no_findings(self, toolkit):
        toolkit._workflow_summary("Test Workflow")

    def test_with_findings(self, toolkit_with_findings):
        toolkit_with_findings._workflow_summary("Test Workflow")

    def test_with_alert(self, toolkit):
        toolkit.findings = [
            {"title": "Critical issue", "severity": "CRITICAL",
             "description": "Bad", "recommendation": "Fix",
             "category": "Test", "nist_function": "Protect"},
        ]
        toolkit.scores = {"test": {"score": 30.0, "grade": "F"}}
        with patch.object(toolkit.alert_mgr, "is_configured",
                          return_value=True), \
             patch.object(toolkit.alert_mgr, "send_alert") as mock_alert:
            toolkit._workflow_summary("Alert Workflow")
            mock_alert.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOWS — Quick Local Ports
# ═══════════════════════════════════════════════════════════════════════════

class TestQuickLocalPorts:

    def test_success(self, toolkit):
        ss_out = (
            "State Recv-Q Send-Q Local:Port Peer:Port\n"
            "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
            "LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n"
        )
        with patch.object(toolkit.cmd, "run",
                          return_value=(0, ss_out, "")):
            toolkit._quick_local_ports()

    def test_fail(self, toolkit):
        with patch.object(toolkit.cmd, "run",
                          return_value=(1, "", "error")):
            toolkit._quick_local_ports()


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOWS — Volatile Data Capture Auto
# ═══════════════════════════════════════════════════════════════════════════

class TestVolatileDataCaptureAuto:

    def test_auto_capture(self, toolkit):
        data = {
            "sections": {"date": {"return_code": 0, "output": "now"}},
        }
        with patch.object(toolkit.evidence, "capture_volatile_data",
                          return_value=data):
            toolkit._volatile_data_capture_auto()


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOWS — Log Analyzer Auto
# ═══════════════════════════════════════════════════════════════════════════

class TestLogAnalyzerAuto:

    def test_with_logs(self, toolkit, sample_auth_log):
        mock_auth = MagicMock()
        mock_auth.exists.return_value = True
        mock_auth.read_text.return_value = sample_auth_log

        mock_syslog = MagicMock()
        mock_syslog.exists.return_value = True
        mock_syslog.read_text.return_value = (
            "Feb 10 10:00:00 server kernel: error\n"
        )

        with patch("cyberguard_toolkit.Path",
                   side_effect=[mock_auth, mock_syslog]):
            toolkit._log_analyzer_auto()

    def test_no_logs(self, toolkit):
        mock_path = MagicMock()
        mock_path.exists.return_value = False
        with patch("cyberguard_toolkit.Path", return_value=mock_path):
            toolkit._log_analyzer_auto()

    def test_permission_denied(self, toolkit):
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.side_effect = PermissionError("denied")
        with patch("cyberguard_toolkit.Path", return_value=mock_path):
            toolkit._log_analyzer_auto()


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOWS — Quick Audit
# ═══════════════════════════════════════════════════════════════════════════

class TestWorkflowQuickAudit:

    def test_quick_audit(self, toolkit):
        with patch.object(toolkit, "_os_security_audit"), \
             patch.object(toolkit, "_quick_local_ports"), \
             patch.object(toolkit, "_failed_login_tracker"), \
             patch.object(toolkit, "_file_permission_audit"), \
             patch.object(toolkit, "_network_connections"), \
             patch.object(toolkit, "_workflow_summary"):
            toolkit._workflow_quick_audit()


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOWS — Full Assessment
# ═══════════════════════════════════════════════════════════════════════════

class TestWorkflowFullAssessment:

    def test_full_assessment(self, toolkit):
        with patch.object(toolkit, "_os_security_audit"), \
             patch.object(toolkit, "_kernel_params"), \
             patch.object(toolkit, "_ssh_hardening"), \
             patch.object(toolkit, "_service_hardening"), \
             patch.object(toolkit, "_file_permission_audit"), \
             patch.object(toolkit, "_user_pam_security"), \
             patch.object(toolkit, "_failed_login_tracker"), \
             patch.object(toolkit.compliance, "run_cis_checks",
                          return_value=[]), \
             patch.object(toolkit, "_workflow_summary"):
            toolkit._workflow_full_assessment()


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOWS — IR Snapshot
# ═══════════════════════════════════════════════════════════════════════════

class TestWorkflowIRSnapshot:

    def test_ir_snapshot(self, toolkit):
        with patch.object(toolkit, "_volatile_data_capture_auto"), \
             patch.object(toolkit, "_network_connections"), \
             patch.object(toolkit, "_process_monitor"), \
             patch.object(toolkit, "_failed_login_tracker"), \
             patch.object(toolkit, "_log_analyzer_auto"), \
             patch.object(toolkit, "_workflow_summary"):
            toolkit._workflow_ir_snapshot()


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOWS — Pre-Deployment
# ═══════════════════════════════════════════════════════════════════════════

class TestWorkflowPreDeployment:

    def test_pre_deployment(self, toolkit):
        with patch.object(toolkit, "_firewall_config_audit"), \
             patch.object(toolkit, "_ssh_hardening"), \
             patch.object(toolkit, "_service_hardening"), \
             patch.object(toolkit, "_file_permission_audit"), \
             patch.object(toolkit, "_kernel_params"), \
             patch.object(toolkit, "_user_pam_security"), \
             patch.object(toolkit, "_workflow_summary"):
            toolkit._workflow_pre_deployment()


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOWS — Monthly Review
# ═══════════════════════════════════════════════════════════════════════════

class TestWorkflowMonthlyReview:

    def test_monthly_review(self, toolkit):
        with patch.object(toolkit, "_full_hardening_report"), \
             patch.object(toolkit, "_config_compliance"), \
             patch.object(toolkit, "_failed_login_tracker"), \
             patch.object(toolkit, "_process_monitor"), \
             patch.object(toolkit, "_network_connections"), \
             patch.object(toolkit, "_nist_csf_compliance"), \
             patch.object(toolkit, "_executive_summary_report"), \
             patch.object(toolkit, "_workflow_summary"):
            toolkit._workflow_monthly_review()


# ═══════════════════════════════════════════════════════════════════════════
# SETTINGS — Manage API Keys
# ═══════════════════════════════════════════════════════════════════════════

class TestManageAPIKeys:

    def test_back(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.side_effect = [None]
            toolkit._manage_api_keys()

    def test_set_key(self, toolkit):
        with patch.object(toolkit.config, "get_api_key",
                          return_value=None), \
             patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask",
                   return_value="new_key_value"):
            mock_sel.return_value.ask.return_value = "virustotal"
            toolkit._manage_api_keys()

    def test_set_key_with_existing(self, toolkit):
        with patch.object(toolkit.config, "get_api_key",
                          return_value="old_key_1234"), \
             patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask",
                   return_value="updated_key"):
            mock_sel.return_value.ask.return_value = "abuseipdb"
            toolkit._manage_api_keys()


# ═══════════════════════════════════════════════════════════════════════════
# SETTINGS — Manage Baselines Menu
# ═══════════════════════════════════════════════════════════════════════════

class TestManageBaselinesMenu:

    def test_delegates_to_fim(self, toolkit):
        with patch.object(toolkit, "_file_integrity_monitor") as mock_fim:
            toolkit._manage_baselines_menu()
            mock_fim.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════
# SETTINGS — Session History
# ═══════════════════════════════════════════════════════════════════════════

class TestSessionHistory:

    def test_no_history(self, toolkit):
        with patch.object(toolkit.config, "load_history",
                          return_value=[]):
            toolkit._session_history()

    def test_with_history(self, toolkit):
        history = [
            {"timestamp": "2026-02-10T10:00:00",
             "session": "abc123def456",
             "action": "quick_audit",
             "details": "5 findings"},
            {"timestamp": "2026-02-10T11:00:00",
             "session": "abc123def456",
             "action": "cis_benchmark",
             "details": "Score: 75"},
        ]
        with patch.object(toolkit.config, "load_history",
                          return_value=history):
            toolkit._session_history()


# ═══════════════════════════════════════════════════════════════════════════
# SETTINGS — About
# ═══════════════════════════════════════════════════════════════════════════

class TestAbout:

    def test_about(self, toolkit):
        toolkit._about()
