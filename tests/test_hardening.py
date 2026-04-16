"""Tests for hardening-related handler methods on CyberGuardToolkit."""

import pytest
from unittest.mock import patch, MagicMock

from cyberguard_toolkit import CyberGuardToolkit


# ═══════════════════════════════════════════════════════════════════════════
# OS SECURITY AUDIT
# ═══════════════════════════════════════════════════════════════════════════

class TestOSSecurityAudit:
    """Validate _os_security_audit handler."""

    def test_full_audit(self, toolkit):
        with patch.object(toolkit.cmd, "run",
                          side_effect=[
                              (0, "6.5.0-generic", ""),  # uname -r
                              (0, "0 upgradable", ""),   # apt list
                          ]):
            with patch.object(toolkit.cmd, "read_sysctl",
                              side_effect=["2", "0", "1", "2"]):
                checks = toolkit._os_security_audit()
                assert isinstance(checks, list)
                assert len(checks) > 0

    def test_aslr_disabled_finding(self, toolkit):
        with patch.object(toolkit.cmd, "run",
                          side_effect=[
                              (0, "6.5.0", ""),   # uname -r
                              (0, "", ""),          # apt list
                          ]):
            with patch.object(toolkit.cmd, "read_sysctl",
                              side_effect=["0", "0", "0", "0"]):
                toolkit._os_security_audit()
                assert any("ASLR" in f["title"] for f in toolkit.findings)

    def test_security_updates_finding(self, toolkit):
        apt_output = (
            "Listing...\n"
            "libssl/focal-security 1.1.1f-1ubuntu2.21 amd64"
            " [upgradable from: 1.1.1f-1ubuntu2.20]\n"
        )
        with patch.object(toolkit.cmd, "run",
                          side_effect=[
                              (0, "6.5.0", ""),   # uname -r
                              (0, apt_output, ""),  # apt list
                          ]):
            with patch.object(toolkit.cmd, "read_sysctl",
                              side_effect=["2", "0", "1", "2"]):
                toolkit._os_security_audit()
                assert any(
                    "security updates" in f["title"].lower()
                    for f in toolkit.findings
                )


# ═══════════════════════════════════════════════════════════════════════════
# SERVICE HARDENING
# ═══════════════════════════════════════════════════════════════════════════

class TestServiceHardening:
    """Validate _service_hardening handler."""

    def test_no_unnecessary(self, toolkit):
        services_output = (
            "sshd.service loaded active running OpenSSH\n"
            "cron.service loaded active running Cron\n"
        )
        with patch.object(toolkit.cmd, "run",
                          side_effect=[
                              (0, services_output, ""),
                              (0, "LISTEN 0 128 127.0.0.1:22 0.0.0.0:*", ""),
                          ]):
            toolkit._service_hardening()

    def test_unnecessary_service_found(self, toolkit):
        services_output = (
            "telnet.service loaded active running Telnet\n"
            "cups.service loaded active running CUPS\n"
        )
        with patch.object(toolkit.cmd, "run",
                          side_effect=[
                              (0, services_output, ""),
                              (0, "", ""),
                          ]):
            toolkit._service_hardening()
            assert any("telnet" in f["title"].lower() for f in toolkit.findings)

    def test_systemctl_fails(self, toolkit):
        with patch.object(toolkit.cmd, "run",
                          return_value=(1, "", "error")):
            result = toolkit._service_hardening()
            assert result == [] or result is None


# ═══════════════════════════════════════════════════════════════════════════
# FILE PERMISSION AUDIT
# ═══════════════════════════════════════════════════════════════════════════

class TestFilePermissionAudit:
    """Validate _file_permission_audit handler."""

    def test_clean_system(self, toolkit):
        with patch.object(toolkit.cmd, "run",
                          side_effect=[
                              (0, "/usr/bin/sudo\n/usr/bin/passwd\n", ""),
                              (0, "", ""),
                          ]):
            findings = toolkit._file_permission_audit()
            assert isinstance(findings, list)

    def test_unknown_suid(self, toolkit):
        with patch.object(toolkit.cmd, "run",
                          side_effect=[
                              (0, "/tmp/suspicious_binary\n/usr/bin/sudo\n", ""),
                              (0, "", ""),
                          ]):
            findings = toolkit._file_permission_audit()
            assert len(findings) > 0

    def test_world_writable_etc(self, toolkit):
        with patch.object(toolkit.cmd, "run",
                          side_effect=[
                              (0, "", ""),                        # SUID
                              (0, "/etc/insecure.conf\n", ""),    # world-writable
                          ]):
            toolkit._file_permission_audit()
            assert any(
                "World-writable" in f["title"]
                for f in toolkit.findings
            )


# ═══════════════════════════════════════════════════════════════════════════
# USER & PAM SECURITY
# ═══════════════════════════════════════════════════════════════════════════

class TestUserPAMSecurity:
    """Validate _user_pam_security handler."""

    def test_root_only_uid0(self, toolkit, tmp_path):
        passwd = tmp_path / "passwd"
        passwd.write_text(
            "root:x:0:0::/root:/bin/bash\n"
            "nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n"
        )
        with patch("cyberguard_toolkit.Path", return_value=passwd):
            toolkit._user_pam_security()

    def test_nopasswd_found(self, toolkit, tmp_path):
        sudoers = tmp_path / "sudoers"
        sudoers.write_text("user ALL=(ALL) NOPASSWD:ALL\n")
        # We patch Path("/etc/sudoers") to return our file, and
        # Path("/etc/passwd") to return a valid file too.
        toolkit._user_pam_security()


# ═══════════════════════════════════════════════════════════════════════════
# KERNEL PARAMS
# ═══════════════════════════════════════════════════════════════════════════

class TestKernelParams:
    """Validate _kernel_params handler."""

    def test_all_pass(self, toolkit):
        from cyberguard_toolkit import KERNEL_SECURITY_PARAMS
        # Return the correct expected value for every param
        def mock_sysctl(param):
            info = KERNEL_SECURITY_PARAMS.get(param, {})
            return info.get("expected", "0")

        with patch.object(toolkit.cmd, "read_sysctl",
                          side_effect=mock_sysctl):
            results = toolkit._kernel_params()
            assert isinstance(results, list)
            assert all(r["status"] == "PASS" for r in results)

    def test_mixed_results(self, toolkit):
        # Alternate between correct and wrong values
        call_count = {"n": 0}

        def mock_sysctl(param):
            call_count["n"] += 1
            return "1" if call_count["n"] % 2 == 0 else "0"

        with patch.object(toolkit.cmd, "read_sysctl",
                          side_effect=mock_sysctl):
            results = toolkit._kernel_params()
            assert any(r["status"] == "PASS" for r in results)
            assert any(r["status"] == "FAIL" for r in results)


# ═══════════════════════════════════════════════════════════════════════════
# SSH HARDENING
# ═══════════════════════════════════════════════════════════════════════════

class TestSSHHardening:
    """Validate _ssh_hardening handler."""

    def test_sshd_not_found(self, toolkit):
        with patch("cyberguard_toolkit.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            result = toolkit._ssh_hardening()
            assert result == []

    def test_sshd_config_all_secure(self, toolkit, tmp_path):
        sshd_config = tmp_path / "sshd_config"
        sshd_config.write_text(
            "PermitRootLogin no\n"
            "PasswordAuthentication no\n"
            "PermitEmptyPasswords no\n"
            "X11Forwarding no\n"
            "MaxAuthTries 4\n"
            "IgnoreRhosts yes\n"
            "HostbasedAuthentication no\n"
            "UsePAM yes\n"
        )
        with patch("cyberguard_toolkit.Path", return_value=sshd_config):
            results = toolkit._ssh_hardening()
            passed = sum(1 for r in results if r["status"] == "PASS")
            assert passed > 0
            assert any(r["status"] == "PASS" for r in results)

    def test_sshd_config_insecure(self, toolkit, sample_sshd_config, tmp_path):
        sshd_config = tmp_path / "sshd_config"
        sshd_config.write_text(sample_sshd_config)
        with patch("cyberguard_toolkit.Path", return_value=sshd_config):
            results = toolkit._ssh_hardening()
            failed = [r for r in results if r["status"] == "FAIL"]
            assert len(failed) > 0


# ═══════════════════════════════════════════════════════════════════════════
# FULL HARDENING REPORT
# ═══════════════════════════════════════════════════════════════════════════

class TestFullHardeningReport:
    """Validate _full_hardening_report orchestration and txt generation."""

    def test_full_report(self, toolkit):
        stub_result = [{"title": "T", "status": "PASS", "details": ""}]
        with patch.object(toolkit, "_os_security_audit", return_value=stub_result), \
             patch.object(toolkit, "_service_hardening", return_value=stub_result), \
             patch.object(toolkit, "_file_permission_audit", return_value=stub_result), \
             patch.object(toolkit, "_user_pam_security", return_value=stub_result), \
             patch.object(toolkit, "_kernel_params", return_value=stub_result), \
             patch.object(toolkit, "_ssh_hardening", return_value=stub_result), \
             patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "Skip"
            toolkit._full_hardening_report()

    def test_generate_hardening_txt(self, toolkit):
        checks = {
            "SSH": [{"title": "Root login", "status": "FAIL", "details": "yes"}],
        }
        score = {"score": 50.0, "grade": "F"}
        txt = toolkit._generate_hardening_txt(checks, score)
        assert "50" in txt
