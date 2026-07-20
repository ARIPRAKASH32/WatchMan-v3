"""
tests/test_risk_engine.py — Unit tests for AI composite risk scoring.
"""
import unittest
from detector.risk_engine import RiskEngine


class TestRiskEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RiskEngine()

    def test_calculate_risk_normal(self):
        score, level = self.engine.calculate_risk(
            rule_alerts=[],
            ml_prediction="Normal",
            rf_confidence=98.0,
            anomaly_score=5.0
        )
        self.assertLess(score, 30)
        self.assertEqual(level, "Low")

    def test_calculate_risk_critical(self):
        alerts = [{
            "type": "SYN Flood",
            "severity": "CRITICAL",
            "confidence": 95
        }]
        score, level = self.engine.calculate_risk(
            rule_alerts=alerts,
            ml_prediction="DoS",
            rf_confidence=96.0,
            anomaly_score=85.0
        )
        self.assertGreaterEqual(score, 80)
        self.assertEqual(level, "Critical")

    def test_get_risk_level(self):
        self.assertEqual(self.engine.get_risk_level(15), "Low")
        self.assertEqual(self.engine.get_risk_level(45), "Medium")
        self.assertEqual(self.engine.get_risk_level(70), "High")
        self.assertEqual(self.engine.get_risk_level(90), "Critical")


if __name__ == "__main__":
    unittest.main()
