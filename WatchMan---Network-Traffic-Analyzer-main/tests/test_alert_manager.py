"""
tests/test_alert_manager.py — Unit tests for alert dispatching and throttling.
"""
import time
import unittest
from detector.alert_manager import AlertManager


class TestAlertManager(unittest.TestCase):
    def setUp(self):
        self.manager = AlertManager()

    def test_deduplication(self):
        # First alert should not be suppressed
        suppressed, reason = self.manager.should_suppress("SYN Flood", "192.168.1.50", 90, 95.0)
        self.assertFalse(suppressed)
        
        # Immediate duplicate should be suppressed due to cooldown
        suppressed, reason = self.manager.should_suppress("SYN Flood", "192.168.1.50", 90, 95.0)
        self.assertTrue(suppressed)
        self.assertIn("cooldown", reason.lower())


if __name__ == "__main__":
    unittest.main()
