"""
tests/test_auto_response.py — Unit tests for automated countermeasures.
"""
import unittest
from detector.auto_response import AutoResponseEngine


class TestAutoResponseEngine(unittest.TestCase):
    def setUp(self):
        self.engine = AutoResponseEngine()

    def test_execute_response_and_block_tracking(self):
        alert = {
            "type": "SYN Flood",
            "src": "10.0.0.50",
            "severity": "CRITICAL",
            "risk_score": 90
        }
        action = self.engine.execute_response(alert)
        self.assertIn("Block", action)
        self.assertIn("10.0.0.50", self.engine.get_blocked_ips())

    def test_duplicate_block(self):
        alert = {
            "type": "SYN Flood",
            "src": "10.0.0.50",
            "severity": "CRITICAL",
            "risk_score": 90
        }
        self.engine.execute_response(alert)
        action = self.engine.execute_response(alert)
        self.assertIn("already blocked", action)


if __name__ == "__main__":
    unittest.main()
