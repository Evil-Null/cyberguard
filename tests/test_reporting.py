"""Tests for HTMLReportGenerator, RemediationTracker, BaselineManager, EvidenceCollector."""

import json
from pathlib import Path

import pytest

from cyberguard_toolkit import (
    BaselineManager,
    EvidenceCollector,
    HTMLReportGenerator,
    RemediationTracker,
)


class TestHTMLReportGenerator:
    """HTMLReportGenerator static report methods return valid HTML."""

    def test_assessment_report(self, sample_findings, sample_scores):
        html = HTMLReportGenerator.assessment_report(sample_findings, sample_scores)
        assert "<!DOCTYPE html>" in html
        assert "CyberGuard" in html
        assert "Security Assessment" in html
        assert "ASLR disabled" in html

    def test_compliance_report(self, sample_cis_results):
        score = {"score": 66.7, "grade": "D", "passed": 2, "total": 3}
        html = HTMLReportGenerator.compliance_report(
            sample_cis_results, "CIS Benchmark", score,
        )
        assert "CIS Benchmark" in html
        assert "66.7" in html
        assert "PASS" in html
        assert "FAIL" in html

    def test_hardening_report(self):
        categories = {
            "SSH": [
                {"title": "Root login", "status": "FAIL", "details": "PermitRootLogin=yes"},
                {"title": "Protocol 2", "status": "PASS", "details": ""},
            ],
        }
        overall = {"score": 50.0, "grade": "F"}
        html = HTMLReportGenerator.hardening_report(categories, overall)
        assert "System Hardening" in html
        assert "50" in html

    def test_vulnerability_report(self):
        vulns = [
            {"id": "SSL-001", "severity": "HIGH", "description": "Deprecated TLS", "affected": "test.com"},
            {"id": "HDR-001", "severity": "MEDIUM", "description": "Missing HSTS", "affected": ""},
        ]
        score = {"score": 70.0, "grade": "C"}
        html = HTMLReportGenerator.vulnerability_report(vulns, score)
        assert "Vulnerability" in html

    def test_executive_summary(self):
        findings = [{"title": "Test finding", "severity": "HIGH", "description": "Test"}]
        html = HTMLReportGenerator.executive_summary(
            grade="B",
            score=85.0,
            findings_count=5,
            top_findings=findings,
            recommendations=["Fix things"],
        )
        assert "Executive" in html
        assert "85" in html

    def test_dark_theme_styles(self):
        html = HTMLReportGenerator.assessment_report([], {})
        assert "#1a1a2e" in html
        assert "#00d4ff" in html


class TestRemediationTracker:
    """RemediationTracker CRUD operations."""

    def test_add_finding(self, remediation):
        item = remediation.add_finding("Test issue", "HIGH", "Description", "Fix it")
        assert item["id"] == 1
        assert item["status"] == "open"
        assert item["severity"] == "HIGH"

    def test_update_status(self, remediation):
        item = remediation.add_finding("Issue", "HIGH")
        remediation.update_status(item["id"], "in-progress", "Working on it")
        items = remediation.get_all()
        assert items[0]["status"] == "in-progress"
        assert len(items[0]["notes"]) == 1

    def test_update_to_resolved(self, remediation):
        item = remediation.add_finding("Issue", "HIGH")
        remediation.update_status(item["id"], "resolved", "Fixed")
        open_items = remediation.get_open()
        assert len(open_items) == 0

    def test_get_open(self, remediation):
        remediation.add_finding("Open 1", "HIGH")
        remediation.add_finding("Open 2", "MEDIUM")
        i3 = remediation.add_finding("Resolved", "LOW")
        remediation.update_status(i3["id"], "resolved")
        open_items = remediation.get_open()
        assert len(open_items) == 2

    def test_get_stats(self, remediation):
        remediation.add_finding("A", "HIGH")
        i2 = remediation.add_finding("B", "MEDIUM")
        remediation.update_status(i2["id"], "resolved")
        stats = remediation.get_stats()
        assert stats.get("open", 0) == 1
        assert stats.get("resolved", 0) == 1

    def test_add_from_findings(self, remediation, sample_findings):
        remediation.add_from_findings(sample_findings)
        items = remediation.get_all()
        assert len(items) >= 3

    def test_update_nonexistent(self, remediation):
        result = remediation.update_status(999, "resolved")
        assert not result


class TestBaselineManager:
    """BaselineManager create/save/load/compare baselines."""

    def test_create_baseline(self, baseline_mgr, tmp_path):
        test_dir = tmp_path / "test_files"
        test_dir.mkdir()
        (test_dir / "file1.txt").write_text("hello")
        (test_dir / "file2.txt").write_text("world")
        baseline = baseline_mgr.create_baseline([str(test_dir)])
        assert "files" in baseline
        assert len(baseline["files"]) == 2

    def test_hash_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h = BaselineManager.hash_file(f)
        assert h is not None
        assert len(h) == 64

    def test_hash_nonexistent(self):
        assert BaselineManager.hash_file(Path("/nonexistent/file")) is None

    def test_save_and_load_baseline(self, baseline_mgr, tmp_path, monkeypatch):
        baselines_dir = tmp_path / "baselines"
        baselines_dir.mkdir()
        monkeypatch.setattr("cyberguard_toolkit.BASELINES_DIR", baselines_dir)
        baseline = {
            "name": "test",
            "timestamp": "2024-01-01",
            "files": {"a": {"hash": "abc"}},
        }
        baseline_mgr.save_baseline(baseline, "test")
        loaded = baseline_mgr.load_baseline("test")
        assert loaded is not None
        assert loaded["name"] == "test"

    def test_list_baselines(self, baseline_mgr, tmp_path, monkeypatch):
        baselines_dir = tmp_path / "baselines"
        baselines_dir.mkdir()
        monkeypatch.setattr("cyberguard_toolkit.BASELINES_DIR", baselines_dir)
        (baselines_dir / "default.json").write_text("{}")
        (baselines_dir / "custom.json").write_text("{}")
        names = baseline_mgr.list_baselines()
        assert "default" in names
        assert "custom" in names

    def test_compare_baseline(self, baseline_mgr, tmp_path):
        files_dir = tmp_path / "files"
        files_dir.mkdir()
        (files_dir / "unchanged.txt").write_text("same")
        (files_dir / "will_change.txt").write_text("original")
        baseline = baseline_mgr.create_baseline([str(files_dir)])

        # Modify one file and add a new one
        (files_dir / "will_change.txt").write_text("modified")
        (files_dir / "new_file.txt").write_text("new")

        diff = baseline_mgr.compare_baseline(baseline)
        assert len(diff["added"]) >= 1


class TestEvidenceCollector:
    """EvidenceCollector file collection and manifest."""

    def test_collect_files(self, evidence, tmp_path, monkeypatch):
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        monkeypatch.setattr("cyberguard_toolkit.EVIDENCE_DIR", evidence_dir)
        (tmp_path / "test1.txt").write_text("evidence content 1")
        (tmp_path / "test2.txt").write_text("evidence content 2")
        manifest = evidence.collect_files(
            [str(tmp_path / "test1.txt"), str(tmp_path / "test2.txt")],
            "test_case",
            "Examiner",
        )
        assert manifest["case_name"] == "test_case"
        collected = [f for f in manifest["files"] if f["status"] == "COLLECTED"]
        assert len(collected) == 2
        assert manifest.get("archive_sha256") is not None

    def test_collect_missing_file(self, evidence, tmp_path, monkeypatch):
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        monkeypatch.setattr("cyberguard_toolkit.EVIDENCE_DIR", evidence_dir)
        manifest = evidence.collect_files(["/nonexistent/file"], "test")
        not_found = [f for f in manifest["files"] if f["status"] == "NOT_FOUND"]
        assert len(not_found) == 1
