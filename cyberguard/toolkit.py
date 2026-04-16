"""CyberGuardToolkit -- thin orchestrator inheriting domain mixins."""
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil
import questionary
from rich.console import Console

from cyberguard.constants import (
    APP_NAME, CONFIG_DIR, HISTORY_FILE, OUTPUT_DIR, SCORES_FILE, TOP_100_PORTS,
    VERSION, Severity,
)
from cyberguard.config import Config, setup_logging
from cyberguard.validators import InputValidator
from cyberguard.commands import SystemCommandRunner
from cyberguard.api import ThreatIntelAPI
from cyberguard.exporter import ResultExporter
from cyberguard.risk import RiskScorer, ExecutiveSummary, ProgressEstimator
from cyberguard.reporting import HTMLReportGenerator
from cyberguard.baseline import BaselineManager
from cyberguard.alerts import AlertManager
from cyberguard.compliance import ComplianceChecker
from cyberguard.remediation import RemediationTracker
from cyberguard.evidence import EvidenceCollector
from cyberguard.ui import UI
from cyberguard.mixins import (
    NetworkMixin, HardeningMixin, VulnMixin, MonitoringMixin,
    ThreatIntelMixin, ForensicsMixin, ReportingMixin, WorkflowsMixin,
)

console = Console()

class CyberGuardToolkit(
    NetworkMixin, HardeningMixin, VulnMixin, MonitoringMixin,
    ThreatIntelMixin, ForensicsMixin, ReportingMixin, WorkflowsMixin,
):
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


    def _human_bytes(n: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if abs(n) < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} PB"

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 2: SYSTEM HARDENING
    # ═══════════════════════════════════════════════════════════════════


    def _firewall_config_audit(self):
        UI.print_section("Firewall Configuration Audit")
        self._firewall_audit()


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


    def _connection_tracker(self):
        UI.print_section("Network Connection Tracker")
        self._network_connections()


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


    def _volatile_data_capture_auto(self):
        """Auto volatile capture for workflow."""
        data = self.evidence.capture_volatile_data("ir_workflow")
        fp = self.exporter.export_json(data, "volatile_ir_workflow")
        UI.print_success(f"Volatile data saved: {fp}")


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
