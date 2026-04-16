"""Tests for ThreatIntelAPI and AlertManager."""

import json

import pytest
from unittest.mock import MagicMock, patch

from cyberguard_toolkit import AlertManager, ThreatIntelAPI


class TestThreatIntelAPI:
    """ThreatIntelAPI VirusTotal, AbuseIPDB, NVD with mocked HTTP."""

    def test_init(self, threat_intel):
        assert threat_intel.config is not None

    def test_vt_no_key(self, threat_intel):
        with pytest.raises(ValueError, match="VirusTotal API key"):
            threat_intel.vt_ip_reputation("8.8.8.8")

    def test_abuse_no_key(self, threat_intel):
        with pytest.raises(ValueError, match="AbuseIPDB API key"):
            threat_intel.abuseipdb_check("8.8.8.8")

    @patch("cyberguard_toolkit.requests.get")
    def test_vt_ip_reputation(self, mock_get, tmp_config):
        tmp_config.save_api_key("virustotal", "test_key")
        api = ThreatIntelAPI(tmp_config)
        mock_resp = MagicMock(
            status_code=200,
            json=lambda: {
                "data": {
                    "attributes": {
                        "as_owner": "Google",
                        "asn": 15169,
                        "country": "US",
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 80,
                        },
                    }
                }
            },
        )
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp
        result = api.vt_ip_reputation("8.8.8.8")
        assert result["data"]["attributes"]["as_owner"] == "Google"

    @patch("cyberguard_toolkit.requests.get")
    def test_vt_hash_reputation(self, mock_get, tmp_config):
        tmp_config.save_api_key("virustotal", "test_key")
        api = ThreatIntelAPI(tmp_config)
        mock_resp = MagicMock(
            status_code=200,
            json=lambda: {
                "data": {
                    "attributes": {
                        "meaningful_name": "malware.exe",
                        "last_analysis_stats": {
                            "malicious": 40,
                            "suspicious": 2,
                        },
                    }
                }
            },
        )
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp
        result = api.vt_hash_reputation("abc123def456")
        assert result["data"]["attributes"]["meaningful_name"] == "malware.exe"

    @patch("cyberguard_toolkit.requests.get")
    def test_abuseipdb_check(self, mock_get, tmp_config):
        tmp_config.save_api_key("abuseipdb", "test_key")
        api = ThreatIntelAPI(tmp_config)
        mock_resp = MagicMock(
            status_code=200,
            json=lambda: {
                "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 85,
                    "isp": "Evil ISP",
                    "totalReports": 42,
                }
            },
        )
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp
        result = api.abuseipdb_check("1.2.3.4")
        assert result["data"]["abuseConfidenceScore"] == 85

    @patch("cyberguard_toolkit.requests.get")
    def test_nvd_cve_lookup(self, mock_get, tmp_config):
        api = ThreatIntelAPI(tmp_config)
        mock_resp = MagicMock(
            status_code=200,
            json=lambda: {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-1234",
                            "descriptions": [
                                {"lang": "en", "value": "Test vuln"},
                            ],
                        }
                    }
                ]
            },
        )
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp
        result = api.nvd_cve_lookup("CVE-2024-1234")
        assert len(result["vulnerabilities"]) == 1

    @patch("cyberguard_toolkit.requests.get")
    def test_caching(self, mock_get, tmp_config):
        tmp_config.save_api_key("virustotal", "test_key")
        api = ThreatIntelAPI(tmp_config)
        mock_resp = MagicMock(
            status_code=200,
            json=lambda: {"data": {"attributes": {"as_owner": "Google"}}},
        )
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp
        api.vt_ip_reputation("8.8.8.8")
        api.vt_ip_reputation("8.8.8.8")
        # Second call should hit cache, so requests.get called only once
        mock_get.assert_called_once()

    @patch("cyberguard_toolkit.requests.get")
    def test_cache_miss(self, mock_get, tmp_config):
        tmp_config.save_api_key("virustotal", "test_key")
        api = ThreatIntelAPI(tmp_config)
        mock_resp = MagicMock(
            status_code=200,
            json=lambda: {"data": {"attributes": {"as_owner": "Google"}}},
        )
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp
        api.vt_ip_reputation("8.8.8.8")
        api.vt_ip_reputation("1.1.1.1")
        # Different IPs = different cache keys, so called twice
        assert mock_get.call_count == 2


class TestAlertManager:
    """AlertManager configure and send alerts."""

    def test_init(self, alert_mgr):
        assert not alert_mgr.is_configured()

    def test_configure_webhook(self, alert_mgr):
        with patch.object(AlertManager, "validate_webhook_url", return_value=True):
            alert_mgr.configure_webhook("https://hooks.slack.com/test", "slack")
        assert alert_mgr.is_configured()

    def test_configure_email(self, alert_mgr):
        alert_mgr.configure_email(
            "smtp.test.com", 587, "user", "pass", "from@test.com", "to@test.com",
        )
        assert alert_mgr.is_configured()

    @patch("cyberguard_toolkit.requests.post")
    def test_send_webhook(self, mock_post, alert_mgr):
        with patch.object(AlertManager, "validate_webhook_url", return_value=True):
            alert_mgr.configure_webhook("https://hooks.slack.com/test", "slack")
        mock_post.return_value = MagicMock(status_code=200)
        alert_mgr.send_alert("Test", "Test message", "HIGH")
        mock_post.assert_called_once()

    def test_save_and_load_config(self, alert_mgr):
        with patch.object(AlertManager, "validate_webhook_url", return_value=True):
            alert_mgr.configure_webhook("https://test.com/webhook", "test")
        alert_mgr._load_config()
        assert "webhooks" in alert_mgr.alerts_config
