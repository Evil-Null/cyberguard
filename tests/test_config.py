"""Tests for Config class — 9 tests."""

import json

from cyberguard_toolkit import Config


class TestConfig:

    def test_init_creates_directories(self, tmp_config):
        assert tmp_config.results_dir.exists()
        assert tmp_config.session_id

    def test_save_and_load_api_key(self, tmp_config):
        tmp_config.save_api_key("virustotal", "test_key_123")
        assert tmp_config.has_api_key("virustotal")
        assert tmp_config.get_api_key("virustotal") == "test_key_123"

    def test_no_api_key(self, tmp_config):
        assert not tmp_config.has_api_key("virustotal")
        assert tmp_config.get_api_key("virustotal") is None

    def test_multiple_api_keys(self, tmp_config):
        tmp_config.save_api_key("virustotal", "vt_key")
        tmp_config.save_api_key("abuseipdb", "abuse_key")
        assert tmp_config.get_api_key("virustotal") == "vt_key"
        assert tmp_config.get_api_key("abuseipdb") == "abuse_key"

    def test_session_history(self, tmp_config):
        tmp_config.save_session_history("test_action", "test details")
        history = tmp_config.load_history()
        assert len(history) >= 1
        assert history[-1]["action"] == "test_action"
        assert history[-1]["details"] == "test details"

    def test_history_limit(self, tmp_config):
        for i in range(10):
            tmp_config.save_session_history(f"action_{i}", f"details_{i}")
        history = tmp_config.load_history(limit=5)
        assert len(history) == 5

    def test_save_score(self, tmp_config):
        tmp_config.save_score("hardening", 85.0, {"checks": 20})
        scores = tmp_config.get_scores()
        assert len(scores) >= 1
        assert scores[0]["score"] == 85.0
        assert scores[0]["category"] == "hardening"

    def test_get_scores_filter(self, tmp_config):
        tmp_config.save_score("hardening", 85.0)
        tmp_config.save_score("ssh", 70.0)
        assert all(s["category"] == "hardening" for s in tmp_config.get_scores("hardening"))
        assert all(s["category"] == "ssh" for s in tmp_config.get_scores("ssh"))

    def test_save_settings(self, tmp_config):
        tmp_config.settings["theme"] = "dark"
        tmp_config.save_settings()
        reloaded = Config()
        assert reloaded.settings["theme"] == "dark"
