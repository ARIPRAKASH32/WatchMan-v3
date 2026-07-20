import time
from collections import defaultdict, deque
from .utils import prune_window, enforce_cap
from .thresholds import get_threshold
from .analyzer import calculate_confidence

_port_window = defaultdict(deque)
WINDOW_SECONDS = 10
_last_alert = {}

def check_portscan(pkt_info, now):
    src = pkt_info['src']
    dst = pkt_info['dst']
    proto = pkt_info['proto']
    dport = pkt_info['dport']
    
    if dport is None or proto not in ("TCP", "UDP") or not src:
        return []
        
    pwin = _port_window[src]
    pwin.append((now, dport))
    
    cutoff = now - WINDOW_SECONDS
    while pwin and pwin[0][0] < cutoff:
        pwin.popleft()
    enforce_cap(_port_window)
    
    unique_ports = len({entry[1] for entry in pwin})
    scan_threshold = get_threshold("PORTSCAN_THRESHOLD")
    
    if unique_ports >= scan_threshold and (now - _last_alert.get(f"scan_{src}", 0) >= 15):
        _last_alert[f"scan_{src}"] = now
        conf = calculate_confidence("portscan", unique_ports, scan_threshold, 90)
        return [{
            "type": "Port Scan Detected",
            "detail": f"{src} probed {unique_ports} unique ports in {WINDOW_SECONDS}s -> {dst} [{proto}]",
            "severity": "HIGH",
            "confidence": conf,
            "mitigation": "Enforce strict firewall rules and block IP"
        }]
    return []
