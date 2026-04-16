"""CyberGuardToolkit forensics domain methods."""
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


class ForensicsMixin:
    """Mixin providing forensics functionality to CyberGuardToolkit."""

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

