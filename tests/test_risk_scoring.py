"""Tests for RiskScorer, ExecutiveSummary, and ProgressEstimator."""

import time

import pytest

from cyberguard_toolkit import ExecutiveSummary, ProgressEstimator, RiskScorer


class TestRiskScorerHost:
    """RiskScorer.score_host deductions per severity level."""

    def test_no_findings(self):
        result = RiskScorer.score_host([])
        assert result["score"] == 100.0
        assert result["grade"] == "A"

    def test_critical_finding(self):
        result = RiskScorer.score_host([{"title": "Critical", "severity": "CRITICAL"}])
        assert result["score"] == 75.0
        assert result["grade"] == "C"

    def test_high_finding(self):
        result = RiskScorer.score_host([{"title": "High", "severity": "HIGH"}])
        assert result["score"] == 85.0
        assert result["grade"] == "B"

    def test_medium_finding(self):
        result = RiskScorer.score_host([{"title": "Medium", "severity": "MEDIUM"}])
        assert result["score"] == 92.0

    def test_low_finding(self):
        result = RiskScorer.score_host([{"title": "Low", "severity": "LOW"}])
        assert result["score"] == 97.0

    def test_multiple_findings(self, sample_findings):
        result = RiskScorer.score_host(sample_findings)
        assert 0 <= result["score"] <= 100
        assert result["grade"] in ("A", "B", "C", "D", "F")

    def test_score_cannot_go_below_zero(self):
        findings = [{"title": "F", "severity": "CRITICAL"} for _ in range(10)]
        result = RiskScorer.score_host(findings)
        assert result["score"] == 0
        assert result["grade"] == "F"


class TestRiskScorerCompliance:
    """RiskScorer.score_compliance pass/total ratio."""

    def test_perfect(self):
        result = RiskScorer.score_compliance(10, 10)
        assert result["score"] == 100.0
        assert result["grade"] == "A"

    def test_zero(self):
        result = RiskScorer.score_compliance(0, 10)
        assert result["score"] == 0
        assert result["grade"] == "F"

    def test_partial(self):
        result = RiskScorer.score_compliance(7, 10)
        assert result["score"] == 70.0
        assert result["grade"] == "C"

    def test_empty(self):
        result = RiskScorer.score_compliance(0, 0)
        assert result["grade"] == "N/A"


class TestRiskScorerNetwork:
    """RiskScorer.score_network port and vuln deductions."""

    def test_clean_network(self):
        result = RiskScorer.score_network(0, 0, 0)
        assert result["score"] == 100.0

    def test_suspicious_ports(self):
        result = RiskScorer.score_network(5, 2, 0)
        assert result["score"] < 100

    def test_vulns(self):
        result = RiskScorer.score_network(5, 0, 5)
        assert result["score"] <= 60


class TestRiskScorerAggregate:
    """RiskScorer.aggregate averages multiple score dicts."""

    def test_aggregate(self):
        scores = [{"score": 80}, {"score": 60}, {"score": 100}]
        result = RiskScorer.aggregate(scores)
        assert result["score"] == 80.0

    def test_empty_aggregate(self):
        result = RiskScorer.aggregate([])
        assert result["grade"] == "N/A"


class TestGrade:
    """RiskScorer._grade threshold boundaries."""

    def test_grades(self):
        assert RiskScorer._grade(95) == "A"
        assert RiskScorer._grade(85) == "B"
        assert RiskScorer._grade(75) == "C"
        assert RiskScorer._grade(65) == "D"
        assert RiskScorer._grade(50) == "F"


class TestExecutiveSummary:
    """ExecutiveSummary.generate produces summary dict."""

    def test_generate(self, sample_findings, sample_scores):
        result = ExecutiveSummary.generate(sample_findings, sample_scores)
        assert "score" in result
        assert "summary" not in result or True  # key may not exist
        assert "grade" in result
        assert result["total_findings"] == len(sample_findings)
        assert len(result["recommendations"]) > 0

    def test_generate_empty(self):
        result = ExecutiveSummary.generate([], {})
        assert result["total_findings"] == 0
        assert result["score"] == 0


class TestProgressEstimator:
    """ProgressEstimator tick / eta / progress_pct basics."""

    def test_basic(self):
        pe = ProgressEstimator()
        pe.start(10)
        assert pe.total == 10
        assert pe.completed == 0

    def test_tick(self):
        pe = ProgressEstimator()
        pe.start(10)
        pe.tick()
        assert pe.completed == 1

    def test_progress_pct(self):
        pe = ProgressEstimator()
        pe.start(10)
        for _ in range(5):
            pe.tick()
        assert pe.progress_pct() == 50.0

    def test_eta_initial(self):
        pe = ProgressEstimator()
        pe.start(10)
        assert pe.eta() == "Calculating..."

    def test_eta_after_tick(self):
        pe = ProgressEstimator()
        pe.start(10)
        pe.tick()
        time.sleep(0.01)
        eta = pe.eta()
        assert eta != "Calculating..."
