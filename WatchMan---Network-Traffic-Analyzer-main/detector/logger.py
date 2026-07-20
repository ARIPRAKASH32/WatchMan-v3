import os
import json
import csv
import time
import logging

log = logging.getLogger("watchman.threat_logger")

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

THREATS_JSON = os.path.join(LOG_DIR, "threats.json")
THREATS_CSV = os.path.join(LOG_DIR, "threats.csv")
ALERTS_LOG = os.path.join(LOG_DIR, "alerts.log")

def log_threat(alert):
    try:
        # JSON Append
        # Read existing, append, write back. Note: NOT efficient for huge files, but OK for this app.
        data = []
        if os.path.exists(THREATS_JSON) and os.path.getsize(THREATS_JSON) > 0:
            with open(THREATS_JSON, "r") as f:
                try:
                    data = json.load(f)
                except:
                    pass
        data.append(alert)
        with open(THREATS_JSON, "w") as f:
            json.dump(data, f, indent=2)
            
        # CSV Append
        file_exists = os.path.exists(THREATS_CSV)
        with open(THREATS_CSV, "a", newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Timestamp", "Threat", "Severity", "Confidence", "Source", "Destination", "Protocol", "Recommendation"])
            writer.writerow([
                alert.get("time"),
                alert.get("type"),
                alert.get("severity"),
                alert.get("confidence"),
                alert.get("src", ""),
                alert.get("dst", ""),
                alert.get("proto", ""),
                alert.get("mitigation", "")
            ])
            
        # Text Log Append
        with open(ALERTS_LOG, "a") as f:
            f.write(f"[{alert.get('time')}] [{alert.get('severity')}] {alert.get('type')} (Conf: {alert.get('confidence')}%) - Src: {alert.get('src')} Dst: {alert.get('dst')} Proto: {alert.get('proto')} Rec: {alert.get('mitigation')}\n")
            
    except Exception as e:
        log.error(f"Failed to log threat: {e}")
