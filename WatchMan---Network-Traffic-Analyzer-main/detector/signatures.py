import time

_last_alert = {}

def check_signatures(pkt_info, now):
    src = pkt_info['src']
    dst = pkt_info['dst']
    proto = pkt_info['proto']
    flags = pkt_info['flags']
    dport = pkt_info['dport']
    
    if not src or not dst:
        return []

    alerts = []
    
    if proto == "TCP" and flags is not None:
        flags_str = str(flags).upper()
        
        # NULL Scan
        if not flags_str and (now - _last_alert.get(f"nullscan_{src}", 0) >= 15):
            _last_alert[f"nullscan_{src}"] = now
            alerts.append({
                "type": "NULL Scan Detected",
                "detail": f"{src} sent TCP packet with NO flags to {dst}:{dport}",
                "severity": "HIGH",
                "confidence": 95,
                "mitigation": "Drop TCP packets missing standard flags"
            })
            
        # XMAS Scan
        elif ("F" in flags_str and "P" in flags_str and "U" in flags_str) and (now - _last_alert.get(f"xmasscan_{src}", 0) >= 15):
            _last_alert[f"xmasscan_{src}"] = now
            alerts.append({
                "type": "XMAS Scan Detected",
                "detail": f"{src} sent TCP XMAS packet (FIN, PSH, URG) to {dst}:{dport}",
                "severity": "HIGH",
                "confidence": 95,
                "mitigation": "Drop invalid combinations (FIN+PSH+URG)"
            })
            
    return alerts
