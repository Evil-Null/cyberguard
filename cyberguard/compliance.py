"""Compliance checking (CIS, NIST, custom frameworks)."""
from __future__ import annotations

import grp
import logging
import os
import pwd
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from cyberguard.commands import SystemCommandRunner

from cyberguard.constants import CIS_CHECKS, Severity

_log = logging.getLogger("cyberguard")

class ComplianceChecker:
    """NIST CSF and CIS Benchmark compliance checking."""

    def __init__(self, cmd_runner: SystemCommandRunner, logger: logging.Logger):
        self.cmd = cmd_runner
        self.logger = logger

    def run_cis_checks(self) -> List[dict]:
        results = []
        for check in CIS_CHECKS:
            cid = check["id"]
            result = {"id": cid, "title": check["title"], "category": check["cat"],
                      "status": "FAIL", "details": ""}
            try:
                if cid == "1.1.1":
                    result = self._check_module_disabled("cramfs", result)
                elif cid == "1.1.2":
                    result = self._check_module_disabled("squashfs", result)
                elif cid == "1.1.3":
                    result = self._check_module_disabled("udf", result)
                elif cid == "1.3.1":
                    result = self._check_package_installed("aide", result)
                elif cid == "1.4.1":
                    result = self._check_grub_password(result)
                elif cid == "1.5.1":
                    result = self._check_aslr(result)
                elif cid == "1.5.3":
                    result = self._check_package_not_installed("prelink", result)
                elif cid == "2.1.1":
                    result = self._check_time_sync(result)
                elif cid.startswith("2.2."):
                    svc_map = {
                        "2.2.1": "xserver-xorg", "2.2.2": "avahi-daemon",
                        "2.2.3": "cups", "2.2.4": "isc-dhcp-server",
                        "2.2.5": "slapd", "2.2.6": "nfs-kernel-server",
                        "2.2.7": "bind9", "2.2.8": "vsftpd",
                        "2.2.9": "apache2", "2.2.10": "dovecot-imapd",
                        "2.2.11": "samba", "2.2.12": "squid",
                        "2.2.13": "snmpd",
                    }
                    pkg = svc_map.get(cid, "")
                    if pkg:
                        result = self._check_package_not_installed(pkg, result)
                elif cid.startswith("3.1.") or cid.startswith("3.2.") or cid.startswith("3.3."):
                    result = self._check_sysctl_param(cid, result)
                elif cid == "3.5.1":
                    result = self._check_firewall_installed(result)
                elif cid == "3.5.2":
                    result = self._check_firewall_default_deny(result)
                elif cid == "4.1.1":
                    result = self._check_package_installed("auditd", result)
                elif cid == "4.1.2":
                    result = self._check_service_enabled("auditd", result)
                elif cid == "4.2.1":
                    result = self._check_package_installed("rsyslog", result)
                elif cid == "4.2.2":
                    result = self._check_service_enabled("rsyslog", result)
                elif cid == "5.1.1":
                    result = self._check_service_enabled("cron", result)
                elif cid == "5.2.1":
                    result = self._check_file_perms("/etc/ssh/sshd_config", 0o600, result)
                elif cid.startswith("5.2."):
                    result = self._check_ssh_param(cid, result)
                elif cid == "5.3.1":
                    result = self._check_password_quality(result)
                elif cid == "5.4.1":
                    result = self._check_password_expiry(result)
                elif cid == "6.1.1":
                    result = self._check_file_perms("/etc/passwd", 0o644, result)
                elif cid == "6.1.2":
                    result = self._check_file_perms("/etc/shadow", 0o640, result)
                elif cid == "6.1.3":
                    result = self._check_file_perms("/etc/group", 0o644, result)
                elif cid == "6.1.4":
                    result = self._check_world_writable(result)
                elif cid == "6.2.1":
                    result = self._check_duplicate_uids(result)
                elif cid == "6.2.3":
                    result = self._check_root_only_uid0(result)
            except Exception as e:
                result["details"] = f"Check error: {e}"
            results.append(result)
        return results

    def _check_module_disabled(self, module: str, result: dict) -> dict:
        rc, out, _ = self.cmd.run(["modprobe", "-n", "-v", module], timeout=5)
        if "install /bin/true" in out or "install /bin/false" in out:
            result["status"] = "PASS"
            result["details"] = f"{module} module is disabled"
        else:
            result["details"] = f"{module} module may be loadable"
        return result

    def _check_package_installed(self, pkg: str, result: dict) -> dict:
        rc, out, _ = self.cmd.run(["dpkg", "-s", pkg], timeout=5)
        if rc == 0 and "Status: install ok installed" in out:
            result["status"] = "PASS"
            result["details"] = f"{pkg} is installed"
        else:
            result["details"] = f"{pkg} is not installed"
        return result

    def _check_package_not_installed(self, pkg: str, result: dict) -> dict:
        rc, out, _ = self.cmd.run(["dpkg", "-s", pkg], timeout=5)
        if rc != 0 or "is not installed" in out:
            result["status"] = "PASS"
            result["details"] = f"{pkg} is not installed"
        else:
            result["details"] = f"{pkg} is installed (should be removed)"
        return result

    def _check_grub_password(self, result: dict) -> dict:
        grub_cfg = Path("/boot/grub/grub.cfg")
        if grub_cfg.exists():
            try:
                content = grub_cfg.read_text(errors="replace")
                if "password" in content.lower():
                    result["status"] = "PASS"
                    result["details"] = "Bootloader password appears set"
                else:
                    result["details"] = "No bootloader password detected"
            except PermissionError:
                result["details"] = "Cannot read grub.cfg (permission denied)"
        else:
            result["details"] = "grub.cfg not found"
        return result

    def _check_aslr(self, result: dict) -> dict:
        val = self.cmd.read_sysctl("kernel.randomize_va_space")
        if val == "2":
            result["status"] = "PASS"
            result["details"] = "Full ASLR enabled (value=2)"
        else:
            result["details"] = f"ASLR value={val} (expected 2)"
        return result

    def _check_time_sync(self, result: dict) -> dict:
        for svc in ["chronyd", "systemd-timesyncd", "ntpd"]:
            rc, out, _ = self.cmd.run(["systemctl", "is-active", svc], timeout=5)
            if rc == 0 and "active" in out:
                result["status"] = "PASS"
                result["details"] = f"Time sync via {svc}"
                return result
        result["details"] = "No time synchronization service active"
        return result

    def _check_sysctl_param(self, cid: str, result: dict) -> dict:
        sysctl_map = {
            "3.1.1": "net.ipv4.ip_forward",
            "3.1.2": "net.ipv4.conf.all.send_redirects",
            "3.2.1": "net.ipv4.conf.all.accept_source_route",
            "3.2.2": "net.ipv4.conf.all.accept_redirects",
            "3.2.3": "net.ipv4.conf.all.secure_redirects",
            "3.2.4": "net.ipv4.conf.all.log_martians",
            "3.2.5": "net.ipv4.icmp_echo_ignore_broadcasts",
            "3.2.6": "net.ipv4.icmp_ignore_bogus_error_responses",
            "3.2.7": "net.ipv4.conf.all.rp_filter",
            "3.2.8": "net.ipv4.tcp_syncookies",
            "3.3.1": "net.ipv6.conf.all.accept_ra",
        }
        param = sysctl_map.get(cid)
        if not param:
            return result
        expected = KERNEL_SECURITY_PARAMS.get(param, {}).get("expected", "0")
        val = self.cmd.read_sysctl(param)
        if val == expected:
            result["status"] = "PASS"
            result["details"] = f"{param} = {val}"
        else:
            result["details"] = f"{param} = {val} (expected {expected})"
        return result

    def _check_firewall_installed(self, result: dict) -> dict:
        for pkg in ["ufw", "iptables", "nftables", "firewalld"]:
            rc, _, _ = self.cmd.run(["dpkg", "-s", pkg], timeout=5)
            if rc == 0:
                result["status"] = "PASS"
                result["details"] = f"Firewall package: {pkg}"
                return result
        result["details"] = "No firewall package installed"
        return result

    def _check_firewall_default_deny(self, result: dict) -> dict:
        rc, out, _ = self.cmd.run(["ufw", "status", "verbose"], timeout=5)
        if rc == 0 and "deny (incoming)" in out.lower():
            result["status"] = "PASS"
            result["details"] = "Default incoming policy is deny"
        else:
            result["details"] = "Default deny not confirmed"
        return result

    def _check_service_enabled(self, svc: str, result: dict) -> dict:
        rc, out, _ = self.cmd.run(["systemctl", "is-enabled", svc], timeout=5)
        if rc == 0 and "enabled" in out:
            result["status"] = "PASS"
            result["details"] = f"{svc} is enabled"
        else:
            result["details"] = f"{svc} is not enabled"
        return result

    def _check_file_perms(self, path: str, expected_mode: int, result: dict) -> dict:
        p = Path(path)
        if not p.exists():
            result["details"] = f"{path} not found"
            return result
        mode = p.stat().st_mode & 0o777
        if mode <= expected_mode:
            result["status"] = "PASS"
            result["details"] = f"{path} permissions: {oct(mode)}"
        else:
            result["details"] = f"{path} permissions: {oct(mode)} (expected <= {oct(expected_mode)})"
        return result

    def _check_ssh_param(self, cid: str, result: dict) -> dict:
        ssh_map = {
            "5.2.4": ("X11Forwarding", "no"),
            "5.2.5": ("MaxAuthTries", "4"),
            "5.2.6": ("IgnoreRhosts", "yes"),
            "5.2.7": ("HostbasedAuthentication", "no"),
            "5.2.8": ("PermitRootLogin", "no"),
            "5.2.9": ("PermitEmptyPasswords", "no"),
        }
        param, expected = ssh_map.get(cid, ("", ""))
        if not param:
            return result
        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            result["details"] = "sshd_config not found"
            return result
        try:
            content = sshd_config.read_text(errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0].lower() == param.lower():
                    val = parts[1]
                    if cid == "5.2.5":
                        if int(val) <= int(expected):
                            result["status"] = "PASS"
                    elif val.lower() == expected.lower():
                        result["status"] = "PASS"
                    result["details"] = f"{param} = {val}"
                    return result
            result["details"] = f"{param} not explicitly set"
        except (OSError, PermissionError):
            result["details"] = "Cannot read sshd_config"
        return result

    def _check_password_quality(self, result: dict) -> dict:
        pam_file = Path("/etc/pam.d/common-password")
        if pam_file.exists():
            try:
                content = pam_file.read_text(errors="replace")
                if "pam_pwquality" in content or "pam_cracklib" in content:
                    result["status"] = "PASS"
                    result["details"] = "Password quality module configured"
                else:
                    result["details"] = "No password quality module found"
            except (OSError, PermissionError):
                result["details"] = "Cannot read PAM config"
        else:
            result["details"] = "PAM password config not found"
        return result

    def _check_password_expiry(self, result: dict) -> dict:
        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            try:
                content = login_defs.read_text(errors="replace")
                for line in content.splitlines():
                    if line.strip().startswith("PASS_MAX_DAYS"):
                        val = line.split()[-1]
                        try:
                            if int(val) <= 365:
                                result["status"] = "PASS"
                                result["details"] = f"PASS_MAX_DAYS = {val}"
                            else:
                                result["details"] = f"PASS_MAX_DAYS = {val} (should be <= 365)"
                        except ValueError:
                            result["details"] = f"Cannot parse PASS_MAX_DAYS: {val}"
                        return result
                result["details"] = "PASS_MAX_DAYS not set"
            except (OSError, PermissionError):
                result["details"] = "Cannot read login.defs"
        else:
            result["details"] = "login.defs not found"
        return result

    def _check_world_writable(self, result: dict) -> dict:
        rc, out, _ = self.cmd.run(
            ["find", "/", "-maxdepth", "3", "-xdev", "-type", "f", "-perm", "-0002",
             "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
            timeout=30
        )
        files = [f for f in out.strip().splitlines() if f]
        if not files:
            result["status"] = "PASS"
            result["details"] = "No world-writable files found"
        else:
            result["details"] = f"Found {len(files)} world-writable file(s)"
        return result

    def _check_duplicate_uids(self, result: dict) -> dict:
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            result["details"] = "/etc/passwd not found"
            return result
        uids = []
        for line in passwd.read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 3:
                uids.append(parts[2])
        dupes = [u for u in set(uids) if uids.count(u) > 1]
        if not dupes:
            result["status"] = "PASS"
            result["details"] = "No duplicate UIDs"
        else:
            result["details"] = f"Duplicate UIDs: {', '.join(dupes)}"
        return result

    def _check_root_only_uid0(self, result: dict) -> dict:
        passwd = Path("/etc/passwd")
        if not passwd.exists():
            result["details"] = "/etc/passwd not found"
            return result
        uid0_users = []
        for line in passwd.read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0":
                uid0_users.append(parts[0])
        if uid0_users == ["root"]:
            result["status"] = "PASS"
            result["details"] = "Only root has UID 0"
        else:
            result["details"] = f"UID 0 accounts: {', '.join(uid0_users)}"
        return result

    def nist_csf_assessment(self, findings: List[dict]) -> dict:
        """Map findings to NIST CSF functions."""
        functions = {
            "Identify": {"score": 100, "items": []},
            "Protect": {"score": 100, "items": []},
            "Detect": {"score": 100, "items": []},
            "Respond": {"score": 100, "items": []},
            "Recover": {"score": 100, "items": []},
        }
        for f in findings:
            cat = f.get("nist_function", "Protect")
            sev = f.get("severity", Severity.LOW)
            d = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 6, "LOW": 2}.get(sev, 2)
            if cat in functions:
                functions[cat]["score"] = max(0, functions[cat]["score"] - d)
                functions[cat]["items"].append(f)
        return functions


# ═══════════════════════════════════════════════════════════════════════════
# EXECUTIVE SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
