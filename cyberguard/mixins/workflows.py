"""CyberGuardToolkit workflows domain methods."""
import logging
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Tuple


class WorkflowsMixin:
    """Mixin providing workflows functionality to CyberGuardToolkit."""

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

