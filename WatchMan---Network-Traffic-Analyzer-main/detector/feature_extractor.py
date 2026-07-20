"""
detector/feature_extractor.py — Feature Extraction engine for ML & IDRS.

Extracts real-time flow and packet features needed for machine learning classification
and anomaly detection:
  - Source IP & Destination IP
  - Protocol (TCP, UDP, ICMP, DNS, HTTP, etc.)
  - Source Port & Destination Port
  - Packet Size (bytes)
  - TCP Flags (encoded/string)
  - Flow Duration (seconds)
  - Bytes per Second (flow rate)
  - Packets per Second (flow rate)

Thread-safe and optimized with bounded flow tracking.
"""

import time
import threading
from collections import defaultdict

class PacketFeatureExtractor:
    """
    Stateful feature extractor that tracks per-flow statistics over time
    and returns rich feature vectors for ML model inference and incident logs.
    """
    def __init__(self, max_flows: int = 10000, flow_timeout: float = 60.0):
        self.max_flows = max_flows
        self.flow_timeout = flow_timeout
        self._flows = {}
        self._lock = threading.RLock()
        self._last_prune = time.time()

    def _get_flow_key(self, src: str, dst: str, sport: int | None, dport: int | None, proto: str) -> tuple:
        """Create a bidirectional flow key to track both directions of a session."""
        if sport is not None and dport is not None:
            endpoints = sorted([(src, sport), (dst, dport)])
            return (endpoints[0][0], endpoints[0][1], endpoints[1][0], endpoints[1][1], proto)
        else:
            endpoints = sorted([src, dst])
            return (endpoints[0], endpoints[1], proto)

    def _prune_expired_flows(self, now: float) -> None:
        """Prune inactive flows to keep memory footprint bounded."""
        if now - self._last_prune < 5.0:
            return
        self._last_prune = now
        expired_keys = [
            k for k, v in self._flows.items() if now - v["last_time"] > self.flow_timeout
        ]
        for k in expired_keys:
            del self._flows[k]

        # If still over limit, drop oldest flows
        if len(self._flows) > self.max_flows:
            sorted_flows = sorted(self._flows.items(), key=lambda x: x[1]["last_time"])
            to_remove = len(self._flows) - self.max_flows
            for i in range(to_remove):
                del self._flows[sorted_flows[i][0]]

    def extract(self, pkt_info: dict, now: float | None = None) -> dict:
        """
        Extract features from a single captured packet plus its historical flow context.

        Args:
            pkt_info: Dictionary from capture queue containing raw packet metadata.
            now: Current timestamp (or None for time.time()).

        Returns:
            Dictionary of extracted features ready for ML prediction and display.
        """
        if now is None:
            now = time.time()

        src = pkt_info.get("src", "Unknown")
        dst = pkt_info.get("dst", "Unknown")
        proto = pkt_info.get("proto", "OTHER")
        size = int(pkt_info.get("size", 0))
        sport = pkt_info.get("sport")
        dport = pkt_info.get("dport")
        flags = pkt_info.get("flags")

        sport_val = int(sport) if sport is not None else 0
        dport_val = int(dport) if dport is not None else 0

        # String representation of TCP flags
        flags_str = str(flags) if flags is not None else "NONE"

        flow_duration = 0.001  # Minimum non-zero duration to avoid div by zero
        packet_count = 1
        byte_count = size

        with self._lock:
            self._prune_expired_flows(now)
            flow_key = self._get_flow_key(src, dst, sport, dport, proto)

            if flow_key not in self._flows:
                self._flows[flow_key] = {
                    "start_time": now,
                    "last_time": now,
                    "packet_count": 1,
                    "byte_count": size,
                }
            else:
                flow = self._flows[flow_key]
                flow["last_time"] = now
                flow["packet_count"] += 1
                flow["byte_count"] += size

                packet_count = flow["packet_count"]
                byte_count = flow["byte_count"]
                duration_calc = now - flow["start_time"]
                if duration_calc > 0.001:
                    flow_duration = duration_calc

        # Calculate rates
        pps = round(packet_count / flow_duration, 2)
        bps = round(byte_count / flow_duration, 2)

        return {
            "src": src,
            "dst": dst,
            "proto": proto,
            "sport": sport_val,
            "dport": dport_val,
            "packet_size": size,
            "tcp_flags": flags_str,
            "packet_rate": pps,          # Packets per second (or flow rate)
            "flow_duration": round(flow_duration, 4),
            "bytes_per_sec": bps,
            "packets_per_sec": pps,      # Explicit requirement alias
            "flow_packets": packet_count,
            "flow_bytes": byte_count,
        }

    def to_numerical_vector(self, features: dict) -> list[float]:
        """
        Convert feature dict to a numerical vector suitable for scikit-learn models.
        Features vector order:
        [proto_code, sport, dport, packet_size, flags_code, flow_duration, bytes_per_sec, packets_per_sec]
        """
        # Protocol encoding map
        proto_map = {
            "TCP": 1, "UDP": 2, "ICMP": 3, "DNS": 4, "HTTP": 5,
            "HTTPS": 6, "SSH": 7, "FTP": 8, "SMTP": 9, "ARP": 10, "DHCP": 11
        }
        proto_code = float(proto_map.get(features.get("proto", "OTHER"), 0))

        # Flags encoding map
        flags_map = {
            "NONE": 0, "S": 1, "SA": 2, "A": 3, "PA": 4, "FA": 5, "R": 6, "RA": 7, "FPU": 8
        }
        flags_str = features.get("tcp_flags", "NONE")
        flags_code = float(flags_map.get(flags_str, 0))

        sport = float(features.get("sport", 0))
        dport = float(features.get("dport", 0))
        size = float(features.get("packet_size", 0))
        duration = float(features.get("flow_duration", 0.001))
        bps = float(features.get("bytes_per_sec", 0))
        pps = float(features.get("packets_per_sec", 0))

        return [proto_code, sport, dport, size, flags_code, duration, bps, pps]

# Global singleton instance for easy imports across engines
extractor = PacketFeatureExtractor()
