"""CyberGuardToolkit hardening domain methods."""
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List


class HardeningMixin:
    """Mixin providing hardening functionality to CyberGuardToolkit."""

    def _os_security_audit(self):
        UI.print_section("OS Security Audit")
        checks = []

        # Kernel version
        rc, out, _ = self.cmd.run(["uname", "-r"], timeout=5)
        kernel = out.strip() if rc == 0 else "Unknown"
        UI.print_info(f"Kernel: {kernel}")

        # ASLR
        val = self.cmd.read_sysctl("kernel.randomize_va_space")
        passed = val == "2"
        checks.append({"title": "ASLR (Address Space Layout Randomization)", "status": "PASS" if passed else "FAIL",
                        "details": f"Value: {val} (expected: 2)"})
        if not passed:
            self._add_finding("ASLR not fully enabled", "HIGH",
                              f"kernel.randomize_va_space = {val} (should be 2)",
                              "Set: sysctl -w kernel.randomize_va_space=2", "Hardening", "Protect")

        # Core dumps
        val = self.cmd.read_sysctl("fs.suid_dumpable")
        passed = val == "0"
        checks.append({"title": "SUID Core Dumps Disabled", "status": "PASS" if passed else "FAIL",
                        "details": f"Value: {val}"})

        # Secure Boot
        sb_path = Path("/sys/firmware/efi/efivars")
        sb = sb_path.exists()
        checks.append({"title": "EFI/UEFI Boot", "status": "PASS" if sb else "FAIL",
                        "details": "EFI boot detected" if sb else "Legacy BIOS boot"})

        # Pending updates
        rc, out, _ = self.cmd.run(["apt", "list", "--upgradable"], timeout=30)
        if rc == 0:
            updates = [l for l in out.splitlines()[1:] if l.strip()]
            security_updates = [u for u in updates if "security" in u.lower()]
            checks.append({"title": "System Updates", "status": "PASS" if not security_updates else "FAIL",
                            "details": f"{len(updates)} pending ({len(security_updates)} security)"})
            if security_updates:
                self._add_finding(f"{len(security_updates)} pending security updates", "HIGH",
                                  "Security updates available",
                                  "Run: sudo apt update && sudo apt upgrade", "Hardening", "Protect")

        # dmesg restriction
        val = self.cmd.read_sysctl("kernel.dmesg_restrict")
        passed = val == "1"
        checks.append({"title": "dmesg Restricted", "status": "PASS" if passed else "FAIL",
                        "details": f"Value: {val}"})

        # kptr_restrict
        val = self.cmd.read_sysctl("kernel.kptr_restrict")
        passed = val in ("1", "2")
        checks.append({"title": "Kernel Pointer Restriction", "status": "PASS" if passed else "FAIL",
                        "details": f"Value: {val}"})

        for c in checks:
            UI.print_check(c["status"], c["title"], c["details"])

        return checks


    def _service_hardening(self):
        UI.print_section("Service Hardening Audit")
        checks = []

        rc, out, _ = self.cmd.run(["systemctl", "list-units", "--type=service", "--state=running",
                                    "--no-pager", "--no-legend"], timeout=15)
        if rc != 0:
            UI.print_error("Cannot list services")
            return checks

        running_services = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                svc = parts[0].replace(".service", "")
                running_services.append(svc)

        unnecessary = [s for s in running_services if s in UNNECESSARY_SERVICES]
        if unnecessary:
            for s in unnecessary:
                UI.print_finding("MEDIUM", f"Unnecessary service running: {s}",
                                 "Consider disabling if not needed")
                checks.append({"title": f"Unnecessary service: {s}", "status": "FAIL",
                                "details": "Running but may not be needed"})
                self._add_finding(f"Unnecessary service: {s}", "MEDIUM",
                                  f"Service {s} is running but may not be needed",
                                  f"Disable with: sudo systemctl disable --now {s}", "Hardening", "Protect")
        else:
            UI.print_success("No common unnecessary services detected")

        # Check for services listening on 0.0.0.0
        rc, out, _ = self.cmd.run(["ss", "-tlnp"], timeout=10)
        if rc == 0:
            wildcard_services = []
            for line in out.splitlines()[1:]:
                if "0.0.0.0:*" in line or "*:*" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        addr = parts[3]
                        proc = parts[-1] if len(parts) > 5 else ""
                        wildcard_services.append(f"{addr} ({proc})")
            if wildcard_services:
                UI.print_warning(f"{len(wildcard_services)} service(s) listening on all interfaces")
                for ws in wildcard_services[:10]:
                    UI.print_info(f"  {ws}")

        return checks


    def _file_permission_audit(self):
        UI.print_section("File Permission Auditor")
        findings_list = []

        # SUID files
        UI.print_subsection("SUID/SGID Files")
        rc, out, _ = self.cmd.run(
            ["find", "/usr", "/bin", "/sbin", "-maxdepth", "3", "-perm", "-4000", "-type", "f"],
            timeout=30,
        )
        known_suid = {
            "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
            "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/mount",
            "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/crontab",
            "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        }
        if rc == 0:
            suid_files = [f.strip() for f in out.splitlines() if f.strip()]
            unknown_suid = [f for f in suid_files if f not in known_suid]
            UI.print_info(f"Total SUID files: {len(suid_files)}")
            if unknown_suid:
                UI.print_warning(f"Non-standard SUID files: {len(unknown_suid)}")
                for f in unknown_suid[:20]:
                    UI.print_finding("MEDIUM", f"Non-standard SUID: {f}")
                    findings_list.append({"title": f"SUID: {f}", "severity": Severity.MEDIUM})

        # World-writable files in /etc
        UI.print_subsection("World-Writable Files")
        rc, out, _ = self.cmd.run(
            ["find", "/etc", "-maxdepth", "2", "-type", "f", "-perm", "-0002"],
            timeout=15,
        )
        if rc == 0:
            ww_files = [f.strip() for f in out.splitlines() if f.strip()]
            if ww_files:
                UI.print_warning(f"World-writable files in /etc: {len(ww_files)}")
                for f in ww_files[:10]:
                    UI.print_finding("HIGH", f"World-writable: {f}")
                    self._add_finding(f"World-writable file: {f}", "HIGH",
                                      "File is writable by any user",
                                      f"Fix: chmod o-w {f}", "Hardening", "Protect")
            else:
                UI.print_success("No world-writable files in /etc")

        # Critical file permissions
        UI.print_subsection("Critical File Permissions")
        critical_files = {
            "/etc/passwd": 0o644, "/etc/shadow": 0o640,
            "/etc/group": 0o644, "/etc/gshadow": 0o640,
            "/etc/ssh/sshd_config": 0o600,
        }
        for fpath, expected in critical_files.items():
            p = Path(fpath)
            if p.exists():
                mode = p.stat().st_mode & 0o777
                passed = mode <= expected
                UI.print_check(
                    "PASS" if passed else "FAIL",
                    f"{fpath}: {oct(mode)}",
                    f"Expected: <= {oct(expected)}" if not passed else "",
                )
                if not passed:
                    self._add_finding(f"Insecure permissions on {fpath}", "HIGH",
                                      f"Current: {oct(mode)}, Expected: <= {oct(expected)}",
                                      f"Fix: chmod {oct(expected)} {fpath}", "Hardening", "Protect")

        return findings_list


    def _user_pam_security(self):
        UI.print_section("User & PAM Security")
        checks = []

        # UID 0 users
        passwd = Path("/etc/passwd")
        if passwd.exists():
            uid0_users = []
            no_shell_users = 0
            for line in passwd.read_text(errors="replace").splitlines():
                parts = line.split(":")
                if len(parts) >= 7:
                    if parts[2] == "0" and parts[0] != "root":
                        uid0_users.append(parts[0])
                    if parts[6] in ("/usr/sbin/nologin", "/bin/false"):
                        no_shell_users += 1

            if uid0_users:
                UI.print_finding("CRITICAL", f"Non-root UID 0 accounts: {', '.join(uid0_users)}")
                self._add_finding("Non-root UID 0 accounts", "CRITICAL",
                                  f"Accounts with UID 0: {', '.join(uid0_users)}",
                                  "Remove or change UID", "Hardening", "Protect")
                checks.append({"title": "Root-only UID 0", "status": "FAIL"})
            else:
                UI.print_success("Only root has UID 0")
                checks.append({"title": "Root-only UID 0", "status": "PASS"})

        # sudo NOPASSWD
        sudoers_dir = Path("/etc/sudoers.d")
        nopasswd_found = False
        for sp in [Path("/etc/sudoers")] + list(sudoers_dir.glob("*") if sudoers_dir.exists() else []):
            try:
                content = sp.read_text(errors="replace")
                if "NOPASSWD" in content:
                    nopasswd_found = True
                    break
            except (OSError, PermissionError):
                continue

        if nopasswd_found:
            UI.print_finding("MEDIUM", "NOPASSWD found in sudoers configuration")
            checks.append({"title": "sudo NOPASSWD", "status": "FAIL"})
        else:
            UI.print_success("No NOPASSWD in sudoers")
            checks.append({"title": "sudo NOPASSWD", "status": "PASS"})

        # Password policy
        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            content = login_defs.read_text(errors="replace")
            for param, expected in [("PASS_MAX_DAYS", "365"), ("PASS_MIN_DAYS", "1"),
                                     ("PASS_MIN_LEN", "8")]:
                for line in content.splitlines():
                    if line.strip().startswith(param):
                        val = line.split()[-1]
                        UI.print_info(f"{param} = {val}")

        return checks


    def _kernel_params(self):
        UI.print_section("Kernel Parameter Security Check")
        results = []
        for param, info in KERNEL_SECURITY_PARAMS.items():
            val = self.cmd.read_sysctl(param)
            passed = val == info["expected"]
            results.append({
                "param": param, "current": val, "expected": info["expected"],
                "status": "PASS" if passed else "FAIL", "desc": info["desc"],
            })
            UI.print_check("PASS" if passed else "FAIL", info["desc"],
                           f"{param} = {val}" if not passed else "")
            if not passed:
                self._add_finding(f"Insecure kernel parameter: {param}", "MEDIUM",
                                  f"Current: {val}, Expected: {info['expected']}",
                                  f"Fix: sysctl -w {param}={info['expected']}", "Hardening", "Protect")

        passed = sum(1 for r in results if r["status"] == "PASS")
        total = len(results)
        score = RiskScorer.score_compliance(passed, total)
        UI.print_score_panel(score["score"], score["grade"], "Kernel Security Score")
        self.scores["kernel"] = score
        return results


    def _ssh_hardening(self):
        UI.print_section("SSH Hardening Audit")
        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            UI.print_error("sshd_config not found")
            return []

        try:
            content = sshd_config.read_text(errors="replace")
        except PermissionError:
            UI.print_error("Cannot read sshd_config (permission denied)")
            return []

        config_values = {}
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                config_values[parts[0]] = parts[1]

        results = []
        for param, info in SSH_SECURITY_PARAMS.items():
            val = config_values.get(param, "not set")
            expected = info["expected"]
            compare = info.get("compare", "eq")
            passed = False

            if val == "not set":
                passed = False
            elif compare == "lte":
                try:
                    passed = int(val) <= int(expected)
                except ValueError:
                    passed = False
            else:
                passed = val.lower() == expected.lower()

            results.append({
                "param": param, "current": val, "expected": expected,
                "status": "PASS" if passed else "FAIL",
                "severity": info["severity"],
            })
            UI.print_check("PASS" if passed else "FAIL", f"{param} = {val}",
                           f"Expected: {expected}" if not passed else "")
            if not passed:
                self._add_finding(f"SSH: {param} = {val}", info["severity"],
                                  f"Expected: {expected}",
                                  f"Set '{param} {expected}' in sshd_config", "Hardening", "Protect")

        passed_count = sum(1 for r in results if r["status"] == "PASS")
        score = RiskScorer.score_compliance(passed_count, len(results))
        UI.print_score_panel(score["score"], score["grade"], "SSH Security Score")
        self.scores["ssh"] = score
        return results


    def _system_hardening_menu(self):
        while True:
            choice = UI.ask_menu("System Hardening", [
                "1) OS Security Audit",
                "2) Service Hardening",
                "3) File Permission Auditor",
                "4) User & PAM Security",
                "5) Kernel Parameter Checker",
                "6) SSH Hardening Audit",
                "7) Firewall Config Audit",
                "8) Full Hardening Report",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._os_security_audit, "2": self._service_hardening,
                "3": self._file_permission_audit, "4": self._user_pam_security,
                "5": self._kernel_params, "6": self._ssh_hardening,
                "7": self._firewall_config_audit, "8": self._full_hardening_report,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")
                    self.config.logger.error(f"Hardening error: {e}", exc_info=True)


    def _full_hardening_report(self):
        UI.print_section("Full System Hardening Report")
        all_checks = {}

        UI.print_info("Running OS Security Audit...")
        all_checks["OS Security"] = self._os_security_audit() or []

        UI.print_info("Running Service Hardening...")
        all_checks["Services"] = self._service_hardening() or []

        UI.print_info("Running File Permission Audit...")
        all_checks["File Permissions"] = self._file_permission_audit() or []

        UI.print_info("Running User & PAM Security...")
        all_checks["User Security"] = self._user_pam_security() or []

        UI.print_info("Running Kernel Parameter Check...")
        all_checks["Kernel Parameters"] = self._kernel_params() or []

        UI.print_info("Running SSH Hardening Audit...")
        all_checks["SSH Security"] = self._ssh_hardening() or []

        # Calculate overall score
        all_findings = [f for f in self.findings if f.get("category") == "Hardening"]
        score = RiskScorer.score_host(all_findings)
        UI.print_score_panel(score["score"], score["grade"], "Overall Hardening Score")
        self.scores["hardening"] = score
        self.config.save_score("hardening", score["score"])

        # Generate HTML report
        html = HTMLReportGenerator.hardening_report(all_checks, score)
        self.exporter.ask_export(
            {"checks": all_checks, "score": score},
            "hardening_report",
            html=html,
            txt=self._generate_hardening_txt(all_checks, score),
        )


    def _generate_hardening_txt(self, checks: dict, score: dict) -> str:
        lines = [f"System Hardening Report", f"Score: {score['score']}/100 (Grade {score['grade']})", ""]
        for cat, items in checks.items():
            lines.append(f"\n--- {cat} ---")
            for item in items:
                st = item.get("status", "?")
                lines.append(f"  [{st}] {item.get('title', '')}: {item.get('details', '')}")
        return "\n".join(lines)

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 3: VULNERABILITY ASSESSMENT
    # ═══════════════════════════════════════════════════════════════════

