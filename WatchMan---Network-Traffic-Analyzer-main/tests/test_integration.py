"""
tests/test_integration.py — End-to-end integration test of the Watch Man AI IDRS pipeline.
"""
import time
import unittest
from detector.detector import start_engine, stop_engine, enqueue_packet
from models import data_store


class TestIDRSIntegration(unittest.TestCase):
    def setUp(self):
        data_store.reset_state()
        start_engine()

    def tearDown(self):
        stop_engine()

    def test_end_to_end_pipeline(self):
        # Enqueue multiple SYN flood packets from same IP
        for _ in range(50):
            enqueue_packet(
                src="192.168.1.150",
                dst="10.0.0.1",
                proto="TCP",
                size=64,
                sport=54321,
                dport=80,
                src_mac="00:11:22:33:44:55",
                dst_mac="66:77:88:99:AA:BB",
                flags="S"
            )
        
        # Allow background detector thread to process queue
        time.sleep(1.5)
        
        # Verify that risk score and alerts were updated
        alerts = data_store.get_alerts()
        self.assertGreater(len(alerts), 0, "Alerts should be generated for SYN flood")
        
        # Check that AI risk score reflects the detection
        snapshot = data_store.get_snapshot()
        self.assertGreater(snapshot["risk_score"], 0, "Composite Risk Score should be > 0 after attack")
        self.assertIsNotNone(snapshot["ml_prediction"])


if __name__ == "__main__":
    unittest.main()
