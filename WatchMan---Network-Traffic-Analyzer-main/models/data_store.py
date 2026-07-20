"""
models/data_store.py — Watch Man shared in-memory state.

Thread-safe store for all captured network data.
All reads/writes are protected by a single reentrant lock.

Fixes vs. original:
  - current_second_count is now included in get_snapshot() under the lock (was a race condition)
  - ip_packet_counts is pruned to prevent unbounded growth
  - get_snapshot() returns a complete, accurate copy
  - add_alert() and clear_alerts() both lock correctly
  - start_time is reset by reset_state() called from start_capture()
"""

import threading
import time
import logging
from collections import defaultdict, deque

from models import database

log = logging.getLogger("watchman.store")

# ── Thread lock ────────────────────────────────────────────────────────────────
_lock = threading.RLock()   # reentrant — safe if same thread calls nested helpers

# ── LAN Devices ────────────────────────────────────────────────────────────────
_devices: dict = {}  # src_ip -> { ip, mac, vendor, first_seen, last_seen, is_active }

# ── Rolling per-second history (last 60 seconds) ──────────────────────────────
MAX_HISTORY = 60
_pps_history: deque = deque(maxlen=MAX_HISTORY)   # [{time, count}, ...]
_cur_second_count: int = 0
_last_second_ts: int = 0

# ── Protocol counters ──────────────────────────────────────────────────────────
_protocol_counts: dict = defaultdict(int)

# ── IP tracking — bounded to top 500 to prevent memory leak ───────────────────
_ip_packet_counts: dict = defaultdict(int)
MAX_TRACKED_IPS = 500

# ── Recent packets ring buffer ─────────────────────────────────────────────────
MAX_RECENT = 500
_recent_packets: deque = deque(maxlen=MAX_RECENT)

# ── Alerts ring buffer ─────────────────────────────────────────────────────────
MAX_ALERTS = 1000
_alerts: deque = deque(maxlen=MAX_ALERTS)

# -- Threat stats
_threat_timeline: dict = defaultdict(int) # timestamp -> count
_attacker_stats: dict = defaultdict(lambda: {"packets": 0, "threats": 0, "risk_score": 0})
_threat_heat: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(int))) # src -> dst -> threat -> count

# -- AI Risk & ML State
_current_risk_score: int = 15
_latest_ml_prediction: str = "Normal"
_latest_anomaly_score: float = 5.0

# ── Global counters ────────────────────────────────────────────────────────────
_total_packets: int = 0
_total_bytes: int = 0
_start_time: float = 0.0


# ══════════════════════════════════════════════════════════════════════════════
#  INIT / RESET
# ══════════════════════════════════════════════════════════════════════════════

def reset_state() -> None:
    """Reset all counters — called once at startup by start_capture()."""
    global _cur_second_count, _last_second_ts, _total_packets, _total_bytes, _start_time

    with _lock:
        _pps_history.clear()
        _protocol_counts.clear()
        _ip_packet_counts.clear()
        _recent_packets.clear()
        _alerts.clear()
        _devices.clear()

        _total_packets = 0
        _total_bytes = 0
        _cur_second_count = 0
        _last_second_ts = int(time.time())
        _start_time = time.time()
        
        global _current_risk_score, _latest_ml_prediction, _latest_anomaly_score
        _current_risk_score = 15
        _latest_ml_prediction = "Normal"
        _latest_anomaly_score = 5.0

    log.info("Data store reset.")


# ══════════════════════════════════════════════════════════════════════════════
#  WRITE OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def record_packet(
    src_ip: str,
    dst_ip: str,
    protocol: str,
    size: int,
    sport: int | None = None,
    dport: int | None = None,
    src_mac: str | None = None,
    dst_mac: str | None = None,
) -> None:
    """
    Record one captured packet.
    Called from the sniffer thread — must be fast and lock-safe.
    """
    global _cur_second_count, _last_second_ts, _total_packets, _total_bytes

    now_ts = int(time.time())
    now_str = time.strftime("%H:%M:%S")

    with _lock:
        # ── Advance the per-second bucket when the clock ticks ────────────
        if now_ts != _last_second_ts:
            # Flush the just-completed second into history
            _pps_history.append({
                "time":  time.strftime("%H:%M:%S", time.localtime(_last_second_ts)),
                "count": _cur_second_count,
            })
            _cur_second_count = 0
            _last_second_ts = now_ts

        _cur_second_count += 1
        _total_packets += 1
        _total_bytes += max(size, 0)    # guard against negative values

        # ── Protocol counter ───────────────────────────────────────────────
        _protocol_counts[protocol] += 1

        # ── LAN Device Tracking ────────────────────────────────────────────
        if src_mac and src_ip:
            if src_ip not in _devices:
                vendor = "Unknown"
                try:
                    from scapy.data import MANUFDB
                    # Attempt safe OUI lookup
                    v = MANUFDB._get_manuf(src_mac)
                    if v: vendor = str(v)
                except Exception:
                    pass

                _devices[src_ip] = {
                    "ip": src_ip,
                    "mac": src_mac,
                    "vendor": vendor,
                    "first_seen": now_ts,
                    "last_seen": now_ts,
                    "is_active": True
                }
            else:
                _devices[src_ip]["last_seen"] = now_ts
                _devices[src_ip]["is_active"] = True
                _devices[src_ip]["mac"] = src_mac  # Update if MAC changed

        # ── IP tracking — prune when we exceed the cap ────────────────────
        _ip_packet_counts[src_ip] += 1
        if len(_ip_packet_counts) > MAX_TRACKED_IPS:
            # Remove the lowest-count IP to keep the dict bounded
            min_ip = min(_ip_packet_counts, key=_ip_packet_counts.__getitem__)
            del _ip_packet_counts[min_ip]

        # ── Recent packets table ───────────────────────────────────────────
        pkt_dict = {
            "src":   src_ip,
            "dst":   dst_ip,
            "proto": protocol,
            "size":  size,
            "sport": sport if sport is not None else "-",
            "dport": dport if dport is not None else "-",
            "time":  now_str,
        }
        _recent_packets.append(pkt_dict)
        _attacker_stats[src_ip]["packets"] += 1
        
        database.insert_packet(pkt_dict)


def update_ai_state(risk_score: int, prediction: str, anomaly: float) -> None:
    """Update live AI metrics for real-time dashboard display."""
    global _current_risk_score, _latest_ml_prediction, _latest_anomaly_score
    with _lock:
        _current_risk_score = int(risk_score)
        _latest_ml_prediction = str(prediction)
        _latest_anomaly_score = round(float(anomaly), 1)


def add_alert(
    alert_type: str, detail: str, severity: str = "MEDIUM", confidence: int = 90,
    mitigation: str = "No mitigation provided.", src: str = "Unknown", dst: str = "Unknown",
    proto: str = "Unknown", ml_prediction: str = "Normal", anomaly_score: float = 0.0,
    risk_score: int = 0, risk_level: str = "Low", action_taken: str = "None",
    recommendations: dict | None = None
) -> None:
    """Append a threat detection alert with rich AI IDRS fields."""
    with _lock:
        now_ts = int(time.time())
        now_str = time.strftime("%H:%M:%S")
        entry = {
            "type":          alert_type,
            "detail":        detail,
            "severity":      severity,
            "confidence":    confidence,
            "mitigation":    mitigation,
            "time":          now_str,
            "src":           src,
            "dst":           dst,
            "proto":         proto,
            "timestamp":     now_ts,
            "ml_prediction": ml_prediction,
            "anomaly_score": anomaly_score,
            "risk_score":    risk_score,
            "risk_level":    risk_level,
            "action_taken":  action_taken,
            "recommendations": recommendations or {}
        }
        _alerts.appendleft(entry) # Newest first in deque
        
        # Threat stats update
        minute_bucket = (now_ts // 60) * 60
        _threat_timeline[minute_bucket] += 1
        
        if src != "Unknown":
            _attacker_stats[src]["threats"] += 1
            weight = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}.get(severity, 1)
            _attacker_stats[src]["risk_score"] = max(_attacker_stats[src]["risk_score"], risk_score)
            
            if dst != "Unknown":
                _threat_heat[src][dst][alert_type] += 1
                if len(_threat_heat) > MAX_TRACKED_IPS:
                     min_src = min(_threat_heat.keys(), key=lambda k: sum(sum(v.values()) for v in _threat_heat[k].values()))
                     del _threat_heat[min_src]

        # Ignore DB error if schema not migrated for new fields yet
        try:
            database.insert_alert({
                "type": alert_type, "detail": detail, "severity": severity,
                "confidence": confidence, "mitigation": mitigation, "time": now_str,
                "ml_prediction": ml_prediction, "anomaly_score": anomaly_score,
                "risk_score": risk_score, "risk_level": risk_level, "action_taken": action_taken
            })
        except Exception as e:
            log.debug(f"DB insert_alert error: {e}")

    log.warning("[ALERT] [%s] %s — %s (Risk: %s/100 | Action: %s)", severity, alert_type, detail, risk_score, action_taken)


def clear_alerts() -> None:
    """Remove all stored alerts (called by the /clear-alerts API endpoint)."""
    with _lock:
        _alerts.clear()
        _threat_timeline.clear()
        _attacker_stats.clear()
        _threat_heat.clear()
    log.info("Alerts cleared via API.")


# ══════════════════════════════════════════════════════════════════════════════
#  READ OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def get_devices() -> list:
    """Return a list of tracked LAN devices."""
    with _lock:
        now = time.time()
        for d in _devices.values():
            if now - d["last_seen"] > 300: # 5 minutes inactivity
                d["is_active"] = False
        return list(_devices.values())

def get_snapshot() -> dict:
    """
    Return a consistent copy of all traffic stats for the REST API.
    current_pps now correctly reflects the in-progress second count.
    """
    with _lock:
        uptime_secs = int(time.time() - _start_time) if _start_time else 0
        top_ips = sorted(
            _ip_packet_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        # Return last 100 packets newest-first
        recent = list(_recent_packets)[-100:]

        return {
            "total_packets":         _total_packets,
            "total_bytes":           _total_bytes,
            "uptime_seconds":        uptime_secs,
            "packets_per_second":    list(_pps_history),          # full history
            "current_pps":           _cur_second_count,           # in-progress second
            "protocol_distribution": dict(_protocol_counts),
            "top_ips":               [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
            "recent_packets":        recent,
            "risk_score":            _current_risk_score,
            "ml_prediction":         _latest_ml_prediction,
            "anomaly_score":         _latest_anomaly_score,
        }


def get_alerts() -> list:
    """Return a copy of the alerts list (newest first)."""
    with _lock:
        return list(_alerts)

def get_threat_stats() -> dict:
    """Return stats for the Threat Detection Dashboard."""
    with _lock:
        # Calculate timeline data
        now_ts = int(time.time())
        timeline = []
        for i in range(15):
            ts = ((now_ts // 60) - i) * 60
            timeline.append({
                "time": time.strftime("%H:%M", time.localtime(ts)),
                "count": _threat_timeline.get(ts, 0)
            })
        timeline.reverse()
        
        # Calculate protocol pie
        threat_protos = defaultdict(int)
        for a in _alerts:
            if "proto" in a and a["proto"] != "Unknown":
                threat_protos[a["proto"]] += 1
                
        # Top Attackers
        top_attackers = []
        for ip, stats in sorted(_attacker_stats.items(), key=lambda x: x[1]["risk_score"], reverse=True)[:10]:
            if stats["threats"] > 0:
                top_attackers.append({
                    "ip": ip,
                    "packets": stats["packets"],
                    "threats": stats["threats"],
                    "risk_score": stats["risk_score"]
                })
                
        return {
            "active_threats": len([a for a in _alerts if now_ts - a.get("timestamp", 0) < 300]),
            "critical_threats": len([a for a in _alerts if a["severity"] == "CRITICAL"]),
            "threats_today": len(_alerts),
            "timeline": timeline,
            "protocol_dist": dict(threat_protos),
            "top_attackers": top_attackers,
            "heat_map": {k: dict(v) for k, v in _threat_heat.items()},
            "ai_risk_score": _current_risk_score,
            "ml_prediction": _latest_ml_prediction,
            "anomaly_score": _latest_anomaly_score,
            "incidents": list(_alerts)
        }
