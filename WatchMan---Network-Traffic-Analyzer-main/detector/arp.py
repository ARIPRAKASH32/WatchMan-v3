from .utils import enforce_cap
import time

_arp_table = {}
_last_alert = {}

def check_arp(pkt_info, now):
    src = pkt_info['src']
    src_mac = pkt_info['src_mac']
    proto = pkt_info['proto']
    
    if proto != "ARP" or not src or not src_mac:
        return []
        
    alerts = []
    known_mac = _arp_table.get(src)
    if known_mac and known_mac != src_mac:
        if (now - _last_alert.get(f"arpspoof_{src}", 0) >= 15):
            _last_alert[f"arpspoof_{src}"] = now
            alerts.append({
                "type": "ARP Spoofing Detected",
                "detail": f"IP {src} changed MAC from {known_mac} to {src_mac}",
                "severity": "CRITICAL",
                "confidence": 99,
                "mitigation": "Implement Dynamic ARP Inspection (DAI)"
            })
            
    _arp_table[src] = src_mac
    enforce_cap(_arp_table)
    return alerts
