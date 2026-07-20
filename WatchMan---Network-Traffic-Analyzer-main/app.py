"""
app.py — Watch Man Flask entry point.

Usage:
    python app.py            # live capture (needs root on Linux)
    python app.py --demo     # simulated traffic (no root required)
    DEMO_MODE=1 python app.py

Fixes vs. original:
  - DEMO_MODE default corrected: os.environ default is "0" not "1" (was always demo)
  - Added /clear-alerts POST endpoint (dashboard "CLEAR" button now works)
  - Added /health endpoint for uptime monitoring
  - Added /api/mode endpoint so the UI can show live vs demo mode
  - File-based logging to logs/watchman.log
  - Graceful Ctrl-C handling via atexit
"""

import os
import sys
import csv
import io
import logging
import atexit
from pathlib import Path

# Ensure project root is in sys.path for clean package imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# pyrefly: ignore [missing-import]
from flask import Flask, jsonify, render_template, Response, request
from utils.system import is_admin, get_os_info
from flask_cors import CORS

# ── Logging — console + rotating file ────────────────────────────────────────
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

from logging.handlers import RotatingFileHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        RotatingFileHandler(LOG_DIR / "watchman.log", maxBytes=5*1024*1024, backupCount=3, encoding="utf-8"),
    ],
)
log = logging.getLogger("watchman.app")

# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
load_dotenv()

from sniffer.capture import start_capture, stop_capture, is_running
from models.data_store import get_snapshot, get_alerts, clear_alerts, get_devices, get_threat_stats
from detector.risk_engine import risk_engine
from blueprints.email_api import email_bp

app = Flask(__name__)
CORS(app)
app.register_blueprint(email_bp)

# ── Determine capture mode ────────────────────────────────────────────────────
# BUG FIX: original defaulted to "1" (always demo); corrected to "0"
DEMO_MODE = "--demo" in sys.argv or os.environ.get("DEMO_MODE", "0") == "1"


# ══════════════════════════════════════════════════════════════════════════════
#  FRONTEND
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Serve the dashboard."""
    return render_template("index.html")


# ══════════════════════════════════════════════════════════════════════════════
#  REST API — READ
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/traffic")
def traffic():
    """Full traffic snapshot (JSON)."""
    return jsonify(get_snapshot())


@app.route("/alerts")
def alerts_endpoint():
    """Threat alerts list, newest first (JSON)."""
    return jsonify(get_alerts())


@app.route("/devices")
def devices():
    """LAN devices tracked (JSON)."""
    return jsonify(get_devices())


@app.route("/api/threat_stats")
def api_threat_stats():
    """Stats for the new Threat Detection dashboard."""
    return jsonify(get_threat_stats())


@app.route("/api/risk_score")
def api_risk_score():
    """Current AI Risk Score & Qualitative Risk Level."""
    snap = get_snapshot()
    score = snap.get("risk_score", 0)
    return jsonify({
        "risk_score": score,
        "risk_level": risk_engine.get_risk_level(score)
    })


@app.route("/api/ml_prediction")
def api_ml_prediction():
    """Current Random Forest Classification & Anomaly Score."""
    snap = get_snapshot()
    return jsonify({
        "prediction": snap.get("ml_prediction", "Normal"),
        "anomaly_score": snap.get("anomaly_score", 0.0)
    })


@app.route("/api/anomaly_score")
def api_anomaly_score():
    """Current Isolation Forest Anomaly Score."""
    snap = get_snapshot()
    return jsonify({
        "anomaly_score": snap.get("anomaly_score", 0.0)
    })


@app.route("/api/incidents")
def api_incidents():
    """All recorded IDRS incidents with AI recommendations and actions taken."""
    return jsonify(get_alerts())


@app.route("/api/top_ips")
def api_top_ips():
    """Top dangerous source IPs ranked by AI risk score and threat count."""
    stats_data = get_threat_stats()
    return jsonify(stats_data.get("top_attackers", []))


@app.route("/stats")
def stats():
    """Summary KPIs for the header widgets."""
    snap = get_snapshot()
    al   = get_alerts()
    critical = sum(1 for a in al if a["severity"] in ("HIGH", "CRITICAL"))

    return jsonify({
        "total_packets":   snap["total_packets"],
        "total_bytes_mb":  round(snap["total_bytes"] / (1024 * 1024), 3),
        "uptime_seconds":  snap["uptime_seconds"],
        "active_alerts":   len(al),
        "critical_alerts": critical,
        "current_pps":     snap["current_pps"],
        "risk_score":      snap.get("risk_score", 0),
        "risk_level":      risk_engine.get_risk_level(snap.get("risk_score", 0)),
        "ml_prediction":   snap.get("ml_prediction", "Normal"),
        "anomaly_score":   snap.get("anomaly_score", 0.0),
        "demo_mode":       DEMO_MODE,
        "capture_alive":   is_running(),
    })


@app.route("/health")
def health():
    """
    Health-check endpoint for uptime monitoring / load-balancer probes.
    Returns HTTP 200 while the sniffer thread is alive.
    """
    alive = is_running()
    return jsonify({"status": "ok" if alive else "degraded", "capture": alive}), (200 if alive else 503)


@app.route("/api/mode")
def api_mode():
    """Return current capture mode."""
    return jsonify({"demo": DEMO_MODE, "live": not DEMO_MODE})


# ══════════════════════════════════════════════════════════════════════════════
#  REST API — WRITE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/clear-alerts", methods=["POST"])
def clear_alerts_endpoint():
    """
    Clear all stored alerts.
    BUG FIX: original had no backend for the dashboard "CLEAR" button.
    """
    clear_alerts()
    log.info("Alerts cleared via /clear-alerts endpoint.")
    return jsonify({"status": "cleared"})


# ══════════════════════════════════════════════════════════════════════════════
#  CSV EXPORT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/export/csv")
def export_csv():
    """Download recent packets as CSV."""
    snap    = get_snapshot()
    packets = snap.get("recent_packets", [])

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["time", "src", "dst", "proto", "size", "sport", "dport"],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(packets)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=traffic_log.csv"},
    )


@app.route("/export/alerts/csv")
def export_alerts_csv():
    """Download alerts as CSV."""
    al = get_alerts()

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "time", "type", "severity", "detail", "src", "dst", "proto",
            "ml_prediction", "anomaly_score", "risk_score", "risk_level", "action_taken"
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(al)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_log.csv"},
    )


from utils.reporter import generate_json_report, generate_pdf_report

@app.route("/export/report/json")
def export_report_json():
    """Download full system report as JSON."""
    return Response(
        generate_json_report(),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=watchman_report.json"}
    )

@app.route("/export/report/pdf")
def export_report_pdf():
    """Download full system report as PDF."""
    pdf_bytes = generate_pdf_report()
    if not pdf_bytes:
        return jsonify({"error": "fpdf2 library is missing. Install with pip install fpdf2"}), 500
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=watchman_report.pdf"}
    )

# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP / SHUTDOWN
# ══════════════════════════════════════════════════════════════════════════════

def _on_exit():
    log.info("Watch Man shutting down — stopping capture thread.")
    stop_capture()


atexit.register(_on_exit)


if __name__ == "__main__":
    banner = [
        "=" * 60,
        "  ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗",
        "  ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║",
        "  ██║ █╗ ██║███████║   ██║   ██║     ███████║",
        "  ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║",
        "  ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║",
        "   ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝",
        "  ███╗   ███╗ █████╗ ███╗   ██╗",
        "  ████╗ ████║██╔══██╗████╗  ██║",
        "  ██╔████╔██║███████║██╔██╗ ██║",
        "  ██║╚██╔╝██║██╔══██║██║╚██╗██║",
        "  ██║ ╚═╝ ██║██║  ██║██║ ╚████║",
        "  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝",
        "",
        f"  OS      : {get_os_info()}",
        f"  Admin   : {'YES' if is_admin() else 'NO (Requires root/Admin for Live Capture)'}",
        f"  Mode    : {'DEMO (simulated traffic)' if DEMO_MODE else 'LIVE/fallback (Scapy)'}",
        "  Dashboard: http://127.0.0.1:5000",
        "  Logs     : logs/watchman.log",
        "=" * 60,
    ]
    print("\n".join(banner))

    from models.database import start_db
    start_db()
    
    start_capture(demo=DEMO_MODE)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
