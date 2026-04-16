"""CyberGuardToolkit reporting_mixin domain methods."""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from cyberguard.constants import Severity


class ReportingMixin:
    """Mixin providing reporting_mixin functionality to CyberGuardToolkit."""

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

