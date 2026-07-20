import json
import os
import threading
import time
import logging

log = logging.getLogger("watchman.thresholds")

# Defaults
THRESHOLDS = {
    "DOS_THRESHOLD": 80,
    "PORTSCAN_THRESHOLD": 12,
    "ARP_THRESHOLD": 5,
    "BRUTE_THRESHOLD": 15
}

_lock = threading.Lock()
CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "rules.json")

def load_thresholds():
    global THRESHOLDS
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
            with _lock:
                for k, v in data.items():
                    if k in THRESHOLDS:
                        THRESHOLDS[k] = v
    except Exception as e:
        log.error(f"Error loading thresholds: {e}")

def get_threshold(key):
    with _lock:
        return THRESHOLDS.get(key, 100)

def watch_config():
    """Background thread to reload config periodically"""
    last_mtime = 0
    while True:
        try:
            if os.path.exists(CONFIG_FILE):
                mtime = os.path.getmtime(CONFIG_FILE)
                if mtime > last_mtime:
                    load_thresholds()
                    last_mtime = mtime
        except Exception:
            pass
        time.sleep(5)

# Start watcher thread
t = threading.Thread(target=watch_config, daemon=True)
t.start()
