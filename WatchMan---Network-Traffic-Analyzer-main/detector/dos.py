import time
from collections import defaultdict, deque
from .utils import prune_window, enforce_cap
from .thresholds import get_threshold
from .analyzer import calculate_confidence

_ip_window = defaultdict(deque)
_icmp_window = defaultdict(deque)
_sys_syn_win = defaultdict(deque)
_udp_window = defaultdict(deque)

WINDOW_SECONDS = 10
_last_alert = {}

def check_dos(pkt_info, now):
    src = pkt_info['src']
    dst = pkt_info['dst']
    proto = pkt_info['proto']
    flags = pkt_info['flags']
    
    if not src:
        return []

    dos_threshold = get_threshold("DOS_THRESHOLD")
    alerts = []
    
    # Packets/sec
    win = _ip_window[src]
    win.append(now)
    prune_window(win, now, WINDOW_SECONDS)
    enforce_cap(_ip_window)
    
    if len(win) >= dos_threshold and (now - _last_alert.get(f"dos_{src}", 0) >= 15):
        conf = calculate_confidence("dos", len(win), dos_threshold, 80)
        alerts.append({
            "type": "DoS Attack",
            "detail": f"{src} sent {len(win)} packets in {WINDOW_SECONDS}s (threshold: {dos_threshold}) -> {dst}",
            "severity": "HIGH",
            "confidence": conf,
            "mitigation": "Enable rate limiting"
        })
        _last_alert[f"dos_{src}"] = now
        
    # ICMP Flood
    if proto == "ICMP":
        iwin = _icmp_window[src]
        iwin.append(now)
        prune_window(iwin, now, WINDOW_SECONDS)
        enforce_cap(_icmp_window)
        icmp_thresh = max(1, dos_threshold // 2)
        if len(iwin) >= icmp_thresh and (now - _last_alert.get(f"icmp_{src}", 0) >= 15):
            conf = calculate_confidence("icmp", len(iwin), icmp_thresh, 85)
            alerts.append({
                "type": "ICMP Flood",
                "detail": f"{src} sent {len(iwin)} ICMP packets in {WINDOW_SECONDS}s",
                "severity": "HIGH",
                "confidence": conf,
                "mitigation": "Disable ICMP echo replies"
            })
            _last_alert[f"icmp_{src}"] = now
            
    # UDP Flood
    if proto == "UDP":
        uwin = _udp_window[src]
        uwin.append(now)
        prune_window(uwin, now, WINDOW_SECONDS)
        enforce_cap(_udp_window)
        udp_thresh = dos_threshold
        if len(uwin) >= udp_thresh and (now - _last_alert.get(f"udp_{src}", 0) >= 15):
            conf = calculate_confidence("udp", len(uwin), udp_thresh, 85)
            alerts.append({
                "type": "UDP Flood",
                "detail": f"{src} sent {len(uwin)} UDP packets in {WINDOW_SECONDS}s",
                "severity": "HIGH",
                "confidence": conf,
                "mitigation": "Rate limit UDP traffic"
            })
            _last_alert[f"udp_{src}"] = now

    # SYN Flood
    if proto == "TCP" and flags and "S" in str(flags).upper():
        sywin = _sys_syn_win[src]
        sywin.append(now)
        prune_window(sywin, now, WINDOW_SECONDS)
        enforce_cap(_sys_syn_win)
        syn_thresh = max(1, dos_threshold // 2)
        if len(sywin) >= syn_thresh and (now - _last_alert.get(f"synflood_{src}", 0) >= 15):
            conf = calculate_confidence("syn", len(sywin), syn_thresh, 90)
            alerts.append({
                "type": "TCP SYN Flood",
                "detail": f"{src} sent {len(sywin)} SYN packets in {WINDOW_SECONDS}s",
                "severity": "CRITICAL",
                "confidence": conf,
                "mitigation": "Enable TCP SYN cookies"
            })
            _last_alert[f"synflood_{src}"] = now
            
    return alerts
