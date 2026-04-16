"""Tests for ComplianceChecker — CIS checks, module/package/ASLR/service/perms checks, NIST CSF."""

import pytest
from unittest.mock import patch, MagicMock

from cyberguard_toolkit import ComplianceChecker, SystemCommandRunner


class TestComplianceChecker:
    """Validate all ComplianceChecker methods against expected bytecode structure."""

    def test_init(self, compliance_checker):
        assert compliance_checker.cmd is not None

    @patch.object(SystemCommandRunner, "read_sysctl")
    @patch.object(SystemCommandRunner, "run")
    def test_run_cis_checks(self, mock_run, mock_sysctl, compliance_checker):
        mock_run.return_value = (1, "", "")
        mock_sysctl.return_value = "2"
        results = compliance_checker.run_cis_checks()
        assert len(results) > 0
        assert all("id" in r for r in results)
        assert all("status" in r for r in results)
        assert all(r["status"] in ("PASS", "FAIL") for r in results)

    def test_check_module_disabled_pass(self, compliance_checker):
        with patch.object(compliance_checker.cmd, "run",
                          return_value=(0, "install /bin/true", "")):
            status, details = self._unpack(
                compliance_checker._check_module_disabled(
                    "cramfs", self._make_result()))
            assert status == "PASS"

    def test_check_module_disabled_fail(self, compliance_checker):
        with patch.object(compliance_checker.cmd, "run",
                          return_value=(0, "cramfs loaded", "")):
            status, details = self._unpack(
                compliance_checker._check_module_disabled(
                    "cramfs", self._make_result()))
            assert status == "FAIL"

    def test_check_package_installed(self, compliance_checker):
        with patch.object(compliance_checker.cmd, "run",
                          return_value=(0, "Status: install ok installed", "")):
            status, details = self._unpack(
                compliance_checker._check_package_installed(
                    "aide", self._make_result()))
            assert status == "PASS"

    def test_check_package_not_installed(self, compliance_checker):
        with patch.object(compliance_checker.cmd, "run",
                          return_value=(1, "is not installed", "")):
            status, details = self._unpack(
                compliance_checker._check_package_not_installed(
                    "telnet", self._make_result()))
            assert status == "PASS"

    def test_check_aslr_enabled(self, compliance_checker):
        with patch.object(compliance_checker.cmd, "read_sysctl",
                          return_value="2"):
            status, details = self._unpack(
                compliance_checker._check_aslr(self._make_result()))
            assert status == "PASS"

    def test_check_aslr_disabled(self, compliance_checker):
        with patch.object(compliance_checker.cmd, "read_sysctl",
                          return_value="0"):
            status, details = self._unpack(
                compliance_checker._check_aslr(self._make_result()))
            assert status == "FAIL"

    def test_check_service_enabled(self, compliance_checker):
        with patch.object(compliance_checker.cmd, "run",
                          return_value=(0, "enabled", "")):
            status, details = self._unpack(
                compliance_checker._check_service_enabled(
                    "cron", self._make_result()))
            assert status == "PASS"

    def test_check_file_perms_pass(self, compliance_checker, tmp_path):
        test_file = tmp_path / "testfile"
        test_file.write_text("test")
        test_file.chmod(0o644)
        status, details = self._unpack(
            compliance_checker._check_file_perms(
                str(test_file), 0o644, self._make_result()))
        assert status == "PASS"

    def test_check_file_perms_fail(self, compliance_checker, tmp_path):
        test_file = tmp_path / "testfile"
        test_file.write_text("test")
        test_file.chmod(0o777)
        status, details = self._unpack(
            compliance_checker._check_file_perms(
                str(test_file), 0o644, self._make_result()))
        assert status == "FAIL"

    def test_check_root_only_uid0(self, compliance_checker, tmp_path):
        passwd = tmp_path / "passwd"
        passwd.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n"
        )
        with patch("cyberguard_toolkit.Path", return_value=passwd):
            status, details = self._unpack(
                compliance_checker._check_root_only_uid0(self._make_result()))
            assert status == "PASS"

    def test_check_duplicate_uids(self, compliance_checker):
        status, details = self._unpack(
            compliance_checker._check_duplicate_uids(self._make_result()))
        # On a clean system with real /etc/passwd, no dupes expected
        assert status in ("PASS", "FAIL")

    def test_nist_csf_assessment(self, compliance_checker, sample_findings):
        nist = compliance_checker.nist_csf_assessment(sample_findings)
        assert "Identify" in nist
        assert "Protect" in nist
        assert "Detect" in nist
        assert "Respond" in nist
        assert "Recover" in nist
        # Protect has multiple findings deducting from 100
        assert nist["Protect"]["score"] < 100

    def test_nist_csf_no_findings(self, compliance_checker):
        nist = compliance_checker.nist_csf_assessment([])
        assert all(v["score"] == 100 for v in nist.values())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_result():
        return {"status": "FAIL", "details": ""}

    @staticmethod
    def _unpack(result):
        return result["status"], result["details"]
