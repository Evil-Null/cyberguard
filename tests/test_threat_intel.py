"""Tests for Threat Intelligence category of CyberGuardToolkit."""

import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from cyberguard_toolkit import CyberGuardToolkit, MITRE_TECHNIQUES


# ═══════════════════════════════════════════════════════════════════════════
# IP REPUTATION (VirusTotal)
# ═══════════════════════════════════════════════════════════════════════════

class TestIPReputation:

    def test_no_api_key(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=False):
            toolkit._ip_reputation()

    def test_no_ip(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._ip_reputation()

    def test_invalid_ip(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value="not-an-ip"):
            toolkit._ip_reputation()

    def test_success(self, toolkit, sample_vt_ip_response):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value="8.8.8.8"), \
             patch.object(toolkit.threat_intel, "vt_ip_reputation",
                          return_value=sample_vt_ip_response):
            toolkit._ip_reputation()

    def test_api_error(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value="8.8.8.8"), \
             patch.object(toolkit.threat_intel, "vt_ip_reputation",
                          side_effect=Exception("API error")):
            toolkit._ip_reputation()


# ═══════════════════════════════════════════════════════════════════════════
# IP ABUSE CHECK (AbuseIPDB)
# ═══════════════════════════════════════════════════════════════════════════

class TestIPAbuseCheck:

    def test_no_api_key(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=False):
            toolkit._ip_abuse_check()

    def test_no_ip(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._ip_abuse_check()

    def test_high_abuse_score(self, toolkit, sample_abuse_response):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value="1.2.3.4"), \
             patch.object(toolkit.threat_intel, "abuseipdb_check",
                          return_value=sample_abuse_response):
            toolkit._ip_abuse_check()
            assert any("abuse" in f["title"].lower() for f in toolkit.findings)

    def test_low_abuse_score(self, toolkit):
        low_resp = {"data": {"abuseConfidenceScore": 10}}
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value="8.8.8.8"), \
             patch.object(toolkit.threat_intel, "abuseipdb_check",
                          return_value=low_resp):
            toolkit._ip_abuse_check()
            assert not any("abuse" in f.get("title", "").lower()
                           for f in toolkit.findings)

    def test_api_error(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value="8.8.8.8"), \
             patch.object(toolkit.threat_intel, "abuseipdb_check",
                          side_effect=Exception("fail")):
            toolkit._ip_abuse_check()


# ═══════════════════════════════════════════════════════════════════════════
# HASH REPUTATION (VirusTotal)
# ═══════════════════════════════════════════════════════════════════════════

class TestHashReputation:

    def test_no_api_key(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=False):
            toolkit._hash_reputation()

    def test_no_hash(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._hash_reputation()

    def test_invalid_hash(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value="not-a-hash"):
            toolkit._hash_reputation()

    def test_malicious_hash(self, toolkit):
        resp = {
            "data": {
                "attributes": {
                    "meaningful_name": "malware.exe",
                    "type_description": "Win32 EXE",
                    "size": 12345,
                    "last_analysis_stats": {
                        "malicious": 45,
                        "suspicious": 2,
                        "harmless": 5,
                        "undetected": 15,
                    },
                }
            }
        }
        sha256 = "d" * 64
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value=sha256), \
             patch.object(toolkit.threat_intel, "vt_hash_reputation",
                          return_value=resp):
            toolkit._hash_reputation()
            assert any("malicious" in f["title"].lower()
                       for f in toolkit.findings)

    def test_clean_hash(self, toolkit):
        resp = {
            "data": {
                "attributes": {
                    "meaningful_name": "clean.exe",
                    "type_description": "Win32 EXE",
                    "size": 1000,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 60,
                        "undetected": 10,
                    },
                }
            }
        }
        sha256 = "a" * 64
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value=sha256), \
             patch.object(toolkit.threat_intel, "vt_hash_reputation",
                          return_value=resp):
            toolkit._hash_reputation()
            assert not any("malicious" in f.get("title", "").lower()
                           for f in toolkit.findings)

    def test_hash_not_found(self, toolkit):
        import requests
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        http_err = requests.exceptions.HTTPError(response=mock_resp)
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask",
                   return_value="b" * 64), \
             patch.object(toolkit.threat_intel, "vt_hash_reputation",
                          side_effect=http_err):
            toolkit._hash_reputation()


# ═══════════════════════════════════════════════════════════════════════════
# WHOIS INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════

class TestWHOISIntelligence:

    def test_no_target(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._whois_intelligence()

    def test_whois_not_found(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="example.com"), \
             patch.object(toolkit.cmd, "has_command", return_value=False):
            toolkit._whois_intelligence()

    def test_whois_success(self, toolkit):
        whois_out = (
            "Domain Name: EXAMPLE.COM\n"
            "Registrar: Example Inc\n"
            "Creation Date: 1995-08-14\n"
        )
        with patch("cyberguard_toolkit.Prompt.ask", return_value="example.com"), \
             patch.object(toolkit.cmd, "has_command", return_value=True), \
             patch.object(toolkit.cmd, "run",
                          return_value=(0, whois_out, "")), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._whois_intelligence()

    def test_whois_fails(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="example.com"), \
             patch.object(toolkit.cmd, "has_command", return_value=True), \
             patch.object(toolkit.cmd, "run",
                          return_value=(1, "", "error")):
            toolkit._whois_intelligence()


# ═══════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK MAPPER
# ═══════════════════════════════════════════════════════════════════════════

class TestMITREATTACKMapper:

    def test_back(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "Back"
            toolkit._mitre_attack_mapper()

    def test_search_by_id(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask", return_value="T1059"):
            mock_sel.return_value.ask.return_value = "Search by technique ID"
            toolkit._mitre_attack_mapper()

    def test_search_by_id_not_found(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask", return_value="T9999"):
            mock_sel.return_value.ask.return_value = "Search by technique ID"
            toolkit._mitre_attack_mapper()

    def test_search_by_keyword(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask", return_value="credential"):
            mock_sel.return_value.ask.return_value = "Search by keyword"
            toolkit._mitre_attack_mapper()

    def test_search_by_keyword_no_match(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask",
                   return_value="zzzznonexistent"):
            mock_sel.return_value.ask.return_value = "Search by keyword"
            toolkit._mitre_attack_mapper()

    def test_browse_all(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "Browse all techniques"
            toolkit._mitre_attack_mapper()

    def test_map_findings_empty(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "Map findings to ATT&CK"
            toolkit._mitre_attack_mapper()

    def test_map_findings_with_data(self, toolkit):
        toolkit.findings = [
            {"title": "SSH root login enabled", "severity": "HIGH"},
            {"title": "Brute force from 10.0.0.1", "severity": "HIGH"},
            {"title": "SUID on /tmp/evil", "severity": "HIGH"},
            {"title": "Suspicious cron job", "severity": "MEDIUM"},
        ]
        with patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "Map findings to ATT&CK"
            toolkit._mitre_attack_mapper()


# ═══════════════════════════════════════════════════════════════════════════
# IoC MANAGER
# ═══════════════════════════════════════════════════════════════════════════

class TestIoCManager:

    def test_back(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "Back"
            toolkit._ioc_manager()

    def test_add_ioc(self, toolkit, tmp_path, monkeypatch):
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE",
                            tmp_path / "iocs.json")
        with patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask",
                   side_effect=["1.2.3.4", "Malicious IP"]):
            mock_sel.return_value.ask.side_effect = ["Add IoC", "ip"]
            toolkit._ioc_manager()

    def test_search_ioc(self, toolkit, tmp_path, monkeypatch):
        iocs_file = tmp_path / "iocs.json"
        iocs_file.write_text(json.dumps([
            {"type": "ip", "value": "1.2.3.4", "description": "bad"},
        ]))
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE", iocs_file)
        with patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask", return_value="1.2.3"):
            mock_sel.return_value.ask.return_value = "Search IoCs"
            toolkit._ioc_manager()

    def test_search_ioc_no_match(self, toolkit, tmp_path, monkeypatch):
        iocs_file = tmp_path / "iocs.json"
        iocs_file.write_text("[]")
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE", iocs_file)
        with patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask", return_value="xyz"):
            mock_sel.return_value.ask.return_value = "Search IoCs"
            toolkit._ioc_manager()

    def test_list_iocs(self, toolkit, tmp_path, monkeypatch):
        iocs_file = tmp_path / "iocs.json"
        iocs_file.write_text(json.dumps([
            {"type": "ip", "value": "1.2.3.4",
             "description": "test", "added": "2026-01-01"},
        ]))
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE", iocs_file)
        with patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "List all IoCs"
            toolkit._ioc_manager()

    def test_list_iocs_empty(self, toolkit, tmp_path, monkeypatch):
        iocs_file = tmp_path / "iocs.json"
        iocs_file.write_text("[]")
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE", iocs_file)
        with patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "List all IoCs"
            toolkit._ioc_manager()

    def test_import_iocs(self, toolkit, tmp_path, monkeypatch):
        iocs_file = tmp_path / "iocs.json"
        iocs_file.write_text("[]")
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE", iocs_file)
        import_file = tmp_path / "import.json"
        import_file.write_text(json.dumps([{"type": "hash", "value": "abc123"}]))
        with patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask",
                   return_value=str(import_file)):
            mock_sel.return_value.ask.return_value = "Import from file"
            toolkit._ioc_manager()

    def test_import_iocs_bad_file(self, toolkit, tmp_path, monkeypatch):
        iocs_file = tmp_path / "iocs.json"
        iocs_file.write_text("[]")
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE", iocs_file)
        with patch("cyberguard_toolkit.questionary.select") as mock_sel, \
             patch("cyberguard_toolkit.Prompt.ask",
                   return_value="/nonexistent"):
            mock_sel.return_value.ask.return_value = "Import from file"
            toolkit._ioc_manager()

    def test_export_iocs(self, toolkit, tmp_path, monkeypatch):
        iocs_file = tmp_path / "iocs.json"
        iocs_file.write_text("[]")
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE", iocs_file)
        with patch("cyberguard_toolkit.questionary.select") as mock_sel:
            mock_sel.return_value.ask.return_value = "Export IoCs"
            toolkit._ioc_manager()


# ═══════════════════════════════════════════════════════════════════════════
# LOAD / SAVE IoCs
# ═══════════════════════════════════════════════════════════════════════════

class TestLoadSaveIoCs:

    def test_load_no_file(self, toolkit, tmp_path, monkeypatch):
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE",
                            tmp_path / "nonexistent.json")
        result = toolkit._load_iocs()
        assert result == []

    def test_load_valid(self, toolkit, tmp_path, monkeypatch):
        iocs_file = tmp_path / "iocs.json"
        iocs_file.write_text('[{"type": "ip", "value": "1.2.3.4"}]')
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE", iocs_file)
        result = toolkit._load_iocs()
        assert len(result) == 1

    def test_load_corrupt(self, toolkit, tmp_path, monkeypatch):
        iocs_file = tmp_path / "iocs.json"
        iocs_file.write_text("not json")
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE", iocs_file)
        result = toolkit._load_iocs()
        assert result == []

    def test_save(self, toolkit, tmp_path, monkeypatch):
        iocs_file = tmp_path / "iocs.json"
        monkeypatch.setattr("cyberguard_toolkit.IOCS_FILE", iocs_file)
        toolkit._save_iocs([{"type": "domain", "value": "evil.com"}])
        assert iocs_file.exists()
        data = json.loads(iocs_file.read_text())
        assert len(data) == 1


# ═══════════════════════════════════════════════════════════════════════════
# BULK IP REPUTATION
# ═══════════════════════════════════════════════════════════════════════════

class TestBulkIPReputation:

    def test_no_api_keys(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=False):
            toolkit._bulk_ip_reputation()

    def test_no_input(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._bulk_ip_reputation()

    def test_no_valid_ips(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask",
                   return_value="invalid,notip"):
            toolkit._bulk_ip_reputation()

    def test_comma_separated_ips(self, toolkit, sample_vt_ip_response):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask",
                   return_value="8.8.8.8,1.1.1.1"), \
             patch.object(toolkit.threat_intel, "vt_ip_reputation",
                          return_value=sample_vt_ip_response), \
             patch.object(toolkit.threat_intel, "abuseipdb_check",
                          return_value={"data": {"abuseConfidenceScore": 10}}), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._bulk_ip_reputation()

    def test_file_input(self, toolkit, tmp_path, sample_vt_ip_response):
        ips_file = tmp_path / "ips.txt"
        ips_file.write_text("8.8.8.8\n1.1.1.1\n")
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask",
                   return_value=str(ips_file)), \
             patch.object(toolkit.threat_intel, "vt_ip_reputation",
                          return_value=sample_vt_ip_response), \
             patch.object(toolkit.threat_intel, "abuseipdb_check",
                          return_value={"data": {"abuseConfidenceScore": 5}}), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._bulk_ip_reputation()

    def test_api_errors_graceful(self, toolkit):
        with patch.object(toolkit.config, "has_api_key", return_value=True), \
             patch("cyberguard_toolkit.Prompt.ask", return_value="8.8.8.8"), \
             patch.object(toolkit.threat_intel, "vt_ip_reputation",
                          side_effect=Exception("fail")), \
             patch.object(toolkit.threat_intel, "abuseipdb_check",
                          side_effect=Exception("fail")), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._bulk_ip_reputation()
