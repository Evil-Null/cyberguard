"""Risk scoring, executive summary, and progress estimation."""
import logging
import time
from typing import Any, Dict, List

from cyberguard.constants import SCORES_FILE, Severity

_log = logging.getLogger("cyberguard")

class RiskScorer:
    """Security risk scoring 0-100 for hosts, networks, compliance."""

    @staticmethod
    def score_host(findings: List[dict]) -> dict:
        score = 100.0
        deductions = []
        for f in findings:
            sev = f.get("severity", Severity.LOW)
            if sev == Severity.CRITICAL:
                d = 25.0
            elif sev == Severity.HIGH:
                d = 15.0
            elif sev == Severity.MEDIUM:
                d = 8.0
            else:
                d = 3.0
            score -= d
            deductions.append({"finding": f.get("title", "Unknown"), "deduction": d})
        score = max(0.0, score)
        grade = RiskScorer._grade(score)
        return {"score": round(score, 1), "grade": grade, "deductions": deductions}

    @staticmethod
    def score_compliance(passed: int, total: int) -> dict:
        if total == 0:
            return {"score": 0, "grade": "N/A", "passed": 0, "total": 0}
        score = (passed / total) * 100
        grade = RiskScorer._grade(score)
        return {"score": round(score, 1), "grade": grade, "passed": passed, "total": total}

    @staticmethod
    def score_network(open_ports: int, suspicious_ports: int, vulns: int) -> dict:
        score = 100.0
        score -= min(open_ports * 2, 30)
        score -= suspicious_ports * 15
        score -= min(vulns * 10, 40)
        score = max(0.0, score)
        return {"score": round(score, 1), "grade": RiskScorer._grade(score)}

    @staticmethod
    def _grade(score: float) -> str:
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    @staticmethod
    def aggregate(scores: List[dict]) -> dict:
        if not scores:
            return {"score": 0, "grade": "N/A"}
        avg = sum(s.get("score", 0) for s in scores) / len(scores)
        return {"score": round(avg, 1), "grade": RiskScorer._grade(avg)}


# ═══════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════


class ExecutiveSummary:
    """Non-technical security summary with grade and recommendations."""

    @staticmethod
    def generate(findings: List[dict], scores: Dict[str, dict]) -> dict:
        all_scores = [s.get("score", 0) for s in scores.values() if isinstance(s, dict)]
        avg_score = sum(all_scores) / len(all_scores) if all_scores else 0
        grade = RiskScorer._grade(avg_score)

        severity_counts = {}
        for f in findings:
            s = f.get("severity", Severity.LOW)
            severity_counts[s] = severity_counts.get(s, 0) + 1

        top = sorted(findings, key=lambda x: {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}.get(x.get("severity", Severity.LOW), 4))

        recommendations = []
        if severity_counts.get("CRITICAL", 0) > 0:
            recommendations.append("Immediately address all CRITICAL findings — these represent active security risks")
        if severity_counts.get("HIGH", 0) > 0:
            recommendations.append("Schedule remediation of HIGH severity findings within 7 days")
        for f in top[:5]:
            if f.get("recommendation"):
                recommendations.append(f["recommendation"])

        return {
            "score": round(avg_score, 1),
            "grade": grade,
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "top_findings": top[:10],
            "recommendations": recommendations[:10],
            "scores": scores,
        }


# ═══════════════════════════════════════════════════════════════════════════
# PROGRESS ESTIMATOR
# ═══════════════════════════════════════════════════════════════════════════


class ProgressEstimator:
    """ETA calculation for batch operations."""

    def __init__(self):
        self.start_time = time.time()
        self.completed = 0
        self.total = 0

    def start(self, total: int):
        self.start_time = time.time()
        self.completed = 0
        self.total = total

    def tick(self):
        self.completed += 1

    def eta(self) -> str:
        if self.completed == 0:
            return "Calculating..."
        elapsed = time.time() - self.start_time
        rate = self.completed / elapsed
        remaining = (self.total - self.completed) / rate if rate > 0 else 0
        if remaining < 60:
            return f"{remaining:.0f}s"
        elif remaining < 3600:
            return f"{remaining / 60:.1f}m"
        else:
            return f"{remaining / 3600:.1f}h"

    def progress_pct(self) -> float:
        return (self.completed / self.total * 100) if self.total > 0 else 0


# ═══════════════════════════════════════════════════════════════════════════
# REMEDIATION TRACKER
# ═══════════════════════════════════════════════════════════════════════════
