import time
from collections import defaultdict, deque
from .utils import prune_window, enforce_cap
from .thresholds import get_threshold
from .analyzer import calculate_confidence

_bf_window = defaultdict(deque)
WINDOW_SECONDS = 60
_last_alert = {}

# Common auth ports: 22 (SSH), 21 (FTP), 23 (Telnet), 3389 (RDP), 445 (SMB)
AUTH_PORTS = {22, 21, 23, 3389, 445}

def check_bruteforce(pkt_info, now):
    src = pkt_info['src']
    dst = pkt_info['dst']
    proto = pkt_info['proto']
    dport = pkt_info['dport']
    
    if proto != "TCP" or dport not in AUTH_PORTS or not src or not dst:
        return []
        
    bf_threshold = get_threshold("BRUTE_THRESHOLD")
    key = f"{src}_{dst}_{dport}"
    
    win = _bf_window[key]
    win.append(now)
    prune_window(win, now, WINDOW_SECONDS)
    enforce_cap(_bf_window)
    
    if len(win) >= bf_threshold and (now - _last_alert.get(f"bf_{key}", 0) >= 30):
        _last_alert[f"bf_{key}"] = now
        conf = calculate_confidence("bruteforce", len(win), bf_threshold, 92)
        service = {22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP", 445: "SMB"}[dport]
        return [{
            "type": "Brute Force Attack",
            "detail": f"{src} made {len(win)} connection attempts to {service} in {WINDOW_SECONDS}s",
            "severity": "HIGH",
            "confidence": conf,
            "mitigation": f"Block source IP via fail2ban or restrict {service} access"
        }]
        
    return []
