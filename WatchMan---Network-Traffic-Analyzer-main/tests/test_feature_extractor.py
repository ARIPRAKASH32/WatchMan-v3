"""
tests/test_feature_extractor.py — Unit tests for IDRS feature engineering.
"""
import time
import unittest
from detector.feature_extractor import PacketFeatureExtractor


class TestPacketFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = PacketFeatureExtractor()

    def test_extract_basic_features(self):
        pkt = {
            "src": "192.168.1.100",
            "dst": "10.0.0.1",
            "proto": "TCP",
            "sport": 12345,
            "dport": 80,
            "size": 512,
            "flags": "S"
        }
        features = self.extractor.extract(pkt, time.time())
        self.assertEqual(features["proto"], "TCP")
        self.assertEqual(features["sport"], 12345)
        self.assertEqual(features["dport"], 80)
        self.assertEqual(features["packet_size"], 512)
        self.assertEqual(features["tcp_flags"], "S")
        self.assertGreaterEqual(features["packets_per_sec"], 1.0)

    def test_to_numerical_vector(self):
        features = {
            "proto": "TCP",
            "sport": 443,
            "dport": 8080,
            "packet_size": 1024,
            "tcp_flags": "SA",
            "flow_duration": 1.5,
            "bytes_per_sec": 682.67,
            "packets_per_sec": 2.0
        }
        vec = self.extractor.to_numerical_vector(features)
        self.assertEqual(len(vec), 8)
        self.assertEqual(vec[0], 1.0)  # TCP code is 1 in proto_map
        self.assertEqual(vec[1], 443.0)
        self.assertEqual(vec[2], 8080.0)
        self.assertEqual(vec[3], 1024.0)


if __name__ == "__main__":
    unittest.main()
