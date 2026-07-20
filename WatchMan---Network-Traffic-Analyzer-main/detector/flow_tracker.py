import time
from collections import defaultdict
from .utils import enforce_cap

_flows = {}

def track_flow(pkt_info, now):
    src = pkt_info['src']
    dst = pkt_info['dst']
    sport = pkt_info['sport']
    dport = pkt_info['dport']
    proto = pkt_info['proto']
    size = pkt_info['size']
    
    if src and dst and sport is not None and dport is not None:
        flow_key = tuple(sorted([f"{src}:{sport}", f"{dst}:{dport}"]) + [proto])
        if flow_key not in _flows:
            _flows[flow_key] = {
                "start_time": now,
                "last_time": now,
                "packet_count": 1,
                "byte_count": size,
                "src": src,
                "dst": dst,
                "proto": proto
            }
        else:
            _flows[flow_key]["last_time"] = now
            _flows[flow_key]["packet_count"] += 1
            _flows[flow_key]["byte_count"] += size
            
        enforce_cap(_flows, 1000)

def get_active_flows():
    return list(_flows.values())
