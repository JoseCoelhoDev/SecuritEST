from typing import List, Dict
from core.models import Finding


class RiskScorer:
    @staticmethod
    def calculate(findings: List[Finding]) -> Dict:
        total_risk = 0.0
        category_scores = {}

        for finding in findings:
            risk = finding.severity * finding.confidence * finding.weight
            total_risk += risk
            category_scores[finding.owasp] = category_scores.get(finding.owasp, 0.0) + risk

        normalized = min(total_risk * 2.5, 100.0)
        final_score = round(max(0.0, 100.0 - normalized), 2)

        if final_score >= 90:
            grade = "Excellent"
        elif final_score >= 75:
            grade = "Good"
        elif final_score >= 50:
            grade = "Moderate Risk"
        elif final_score >= 25:
            grade = "High Risk"
        else:
            grade = "Critical Risk"

        return {
            "final_score": final_score,
            "grade": grade,
            "category_scores": category_scores
        }