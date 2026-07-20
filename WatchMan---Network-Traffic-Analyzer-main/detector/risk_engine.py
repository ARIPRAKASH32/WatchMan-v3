"""
detector/risk_engine.py — AI Risk Engine for IDRS.

Calculates a composite Risk Score between 0–100 combining:
  1. Rule-based IDS detection score (severity weight)
  2. Random Forest prediction confidence
  3. Isolation Forest anomaly score

Maps the final score to Risk Levels:
  0–30  → Low
  31–60 → Medium
  61–80 → High
  81–100 → Critical
"""

import logging

log = logging.getLogger("watchman.risk")

class RiskEngine:
    """
    Computes real-time risk evaluations for captured network traffic and incidents.
    """
    def __init__(self, rule_weight: float = 0.4, rf_weight: float = 0.4, if_weight: float = 0.2):
        self.rule_weight = rule_weight
        self.rf_weight = rf_weight
        self.if_weight = if_weight

    def calculate_risk(
        self,
        rule_alerts: list[dict],
        ml_prediction: str,
        rf_confidence: float,
        anomaly_score: float
    ) -> tuple[int, str]:
        """
        Compute composite risk score (0-100) and return (score, risk_level_string).

        Args:
            rule_alerts: List of rule-based alert dicts generated for this packet/flow.
            ml_prediction: Predicted class from Random Forest ('Normal', 'DoS', etc.).
            rf_confidence: Confidence percentage (0.0 - 100.0) from Random Forest.
            anomaly_score: Anomaly score percentage (0.0 - 100.0) from Isolation Forest.

        Returns:
            Tuple of (risk_score_int [0..100], risk_level_string ['Low', 'Medium', 'High', 'Critical'])
        """
        # 1. Rule-based contribution (0 to 100)
        rule_score = 0.0
        if rule_alerts:
            # Take the highest severity alert triggered
            severity_map = {
                "CRITICAL": 100.0,
                "HIGH": 78.0,
                "MEDIUM": 52.0,
                "LOW": 25.0
            }
            max_sev = max(severity_map.get(a.get("severity", "LOW"), 25.0) for a in rule_alerts)
            rule_score = max_sev

        # 2. Random Forest contribution (0 to 100)
        rf_score = 0.0
        if ml_prediction and ml_prediction.lower() != "normal":
            # If an attack is predicted, confidence scales between 50 and 100
            rf_score = max(50.0, float(rf_confidence))
        else:
            # If normal is predicted, risk from RF is minimal unless confidence is low
            rf_score = max(0.0, 100.0 - float(rf_confidence))

        # 3. Anomaly score contribution (0 to 100)
        if_score = max(0.0, min(100.0, float(anomaly_score)))

        # Weighted combination
        composite = (
            self.rule_weight * rule_score +
            self.rf_weight * rf_score +
            self.if_weight * if_score
        )

        # If a critical rule fired or RF is extremely confident in an attack, ensure minimum floor
        if rule_score >= 100.0 or (ml_prediction != "Normal" and rf_confidence >= 90.0):
            composite = max(composite, 82.0)
        elif rule_score >= 75.0:
            composite = max(composite, 65.0)

        risk_score = int(round(max(0.0, min(100.0, composite))))
        risk_level = self.get_risk_level(risk_score)

        return risk_score, risk_level

    @staticmethod
    def get_risk_level(score: int | float) -> str:
        """Map numeric risk score to qualitative level according to requirements."""
        score = int(score)
        if score <= 30:
            return "Low"
        elif score <= 60:
            return "Medium"
        elif score <= 80:
            return "High"
        else:
            return "Critical"

# Singleton instance
risk_engine = RiskEngine()
