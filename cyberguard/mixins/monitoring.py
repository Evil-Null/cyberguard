"""CyberGuardToolkit monitoring domain methods."""
import hashlib
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


class MonitoringMixin:
    """Mixin providing monitoring functionality to CyberGuardToolkit."""

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

