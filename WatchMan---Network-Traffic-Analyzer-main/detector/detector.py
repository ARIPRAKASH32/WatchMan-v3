import threading
import queue
import time
import logging

from .dos import check_dos
from .portscan import check_portscan
from .arp import check_arp
from .bruteforce import check_bruteforce
from .signatures import check_signatures
from .flow_tracker import track_flow
from .logger import log_threat
from models import data_store

from .feature_extractor import extractor
from .ml_models import ml_manager
from .risk_engine import risk_engine
from .alert_manager import alert_manager
from .auto_response import auto_response
from .recommendation_engine import recommendation_engine

log = logging.getLogger("watchman.detector")

_pkt_queue = queue.Queue(maxsize=10000)
_running = False
_worker_threads = []

def enqueue_packet(src, dst, proto, size, sport, dport, src_mac, dst_mac, flags):
    if not _running:
        return
    try:
        _pkt_queue.put_nowait({
            'src': src, 'dst': dst, 'proto': proto, 'size': size,
            'sport': sport, 'dport': dport, 'src_mac': src_mac,
            'dst_mac': dst_mac, 'flags': flags
        })
    except queue.Full:
        pass # Drop packet if queue is full

def _process_queue():
    while _running:
        try:
            pkt_info = _pkt_queue.get(timeout=1.0)
            now = time.time()
            
            # Flow Tracking
            track_flow(pkt_info, now)
            
            # Feature Extraction & ML Inference
            features = extractor.extract(pkt_info, now)
            vec = extractor.to_numerical_vector(features)
            prediction, conf = ml_manager.predict_traffic(vec)
            anomaly = ml_manager.anomaly_score(vec)
            
            # Threat Rules
            alerts = []
            alerts.extend(check_dos(pkt_info, now))
            alerts.extend(check_portscan(pkt_info, now))
            alerts.extend(check_arp(pkt_info, now))
            alerts.extend(check_bruteforce(pkt_info, now))
            alerts.extend(check_signatures(pkt_info, now))
            
            # Check if ML or Anomaly detected an attack even without rule trigger
            if not alerts and ((prediction != "Normal" and conf >= 75.0) or anomaly >= 70.0):
                attack_label = prediction if prediction != "Normal" else "Anomaly / Unknown Attack"
                alerts.append({
                    "type": attack_label,
                    "detail": f"AI detected {attack_label} (Conf: {conf}%, Anomaly: {anomaly}%)",
                    "severity": "HIGH" if conf >= 85.0 or anomaly >= 80.0 else "MEDIUM",
                    "confidence": int(conf),
                    "mitigation": "Review AI recommendations and inspect packet flow."
                })
                
            # Compute Risk Score & Level
            risk_score, risk_level = risk_engine.calculate_risk(alerts, prediction, conf, anomaly)
            data_store.update_ai_state(risk_score, prediction, anomaly)
            
            # Alert & Response Generator
            for alert in alerts:
                alert["src"] = pkt_info.get("src", "Unknown")
                alert["dst"] = pkt_info.get("dst", "Unknown")
                alert["proto"] = pkt_info.get("proto", "Unknown")
                alert["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
                alert["ml_prediction"] = prediction
                alert["anomaly_score"] = anomaly
                alert["risk_score"] = risk_score
                alert["risk_level"] = risk_level
                
                # AI Recommendations
                recs = recommendation_engine.get_recommendations(alert["type"], risk_score, alert["detail"])
                alert["recommendations"] = recs
                
                # Auto Response Engine for Critical Risk (>80)
                if risk_score > 80:
                    action_summary = auto_response.execute_response(alert)
                else:
                    action_summary = "Monitored / No auto-response required"
                alert["action_taken"] = action_summary
                
                # Store Correlation & Alert
                data_store.add_alert(
                    alert_type=alert["type"],
                    detail=alert["detail"],
                    severity=alert["severity"],
                    confidence=alert.get("confidence", int(conf)),
                    mitigation=alert.get("mitigation", ""),
                    src=alert["src"],
                    dst=alert["dst"],
                    proto=alert["proto"],
                    ml_prediction=prediction,
                    anomaly_score=anomaly,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    action_taken=action_summary,
                    recommendations=recs
                )
                
                # Dispatch Multi-Channel Automated Alerts
                alert_manager.process_and_dispatch(alert)
                
                # Log to disk
                log_threat(alert)
                
            _pkt_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            log.error(f"Error processing packet: {e}")

def start_engine(num_workers=2):
    global _running
    if _running:
        return
    _running = True
    for _ in range(num_workers):
        t = threading.Thread(target=_process_queue, daemon=True)
        t.start()
        _worker_threads.append(t)
    log.info(f"Threat Detection Engine started with {num_workers} workers.")

def stop_engine():
    global _running
    _running = False
    for t in _worker_threads:
        t.join(timeout=2.0)
    _worker_threads.clear()
