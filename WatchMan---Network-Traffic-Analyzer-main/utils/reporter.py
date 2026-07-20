"""
utils/reporter.py — WatchMan Report Generation
"""
import json
import logging
from models.data_store import get_alerts, get_snapshot, get_devices

log = logging.getLogger("watchman.reporter")

def generate_json_report() -> str:
    """Generate a cohesive JSON string of all current state."""
    snap = get_snapshot()
    alerts = get_alerts()
    devices = get_devices()
    return json.dumps({
        "traffic_snapshot": snap,
        "threat_alerts": alerts,
        "lan_devices": devices
    }, indent=2)


def generate_pdf_report() -> bytes:
    """Generate a PDF binary string representing the current system state."""
    try:
        from fpdf import FPDF
    except ImportError:
        log.error("fpdf2 not installed. Run 'pip install fpdf2'")
        return b""
        
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", style="B", size=18)
    pdf.cell(200, 10, "WatchMan IDS Security Report", ln=True, align="C")
    
    snap = get_snapshot()
    alerts = get_alerts()
    devices = get_devices()
    
    pdf.set_font("Helvetica", size=12)
    pdf.ln(10)
    pdf.cell(200, 10, f"Total Packets Captured: {snap['total_packets']}", ln=True)
    pdf.cell(200, 10, f"Total Data Processed (MB): {snap['total_bytes'] / (1024*1024):.2f}", ln=True)
    pdf.cell(200, 10, f"Current AI Risk Score: {snap.get('risk_score', 0)} / 100", ln=True)
    pdf.cell(200, 10, f"Latest ML Prediction: {snap.get('ml_prediction', 'Normal')} (Anomaly Score: {snap.get('anomaly_score', 0.0)})", ln=True)
    pdf.cell(200, 10, f"Critical Threats: {len([a for a in alerts if a['severity'] == 'CRITICAL'])}", ln=True)
    pdf.cell(200, 10, f"Total Network Alerts: {len(alerts)}", ln=True)
    pdf.cell(200, 10, f"Tracked LAN Devices: {len(devices)}", ln=True)
    
    pdf.ln(10)
    pdf.set_font("Helvetica", style="B", size=14)
    pdf.cell(200, 10, "AI Threat & Incident Log (Top High/Critical):", ln=True)
    pdf.set_font("Helvetica", size=10)
    
    high_alerts = [a for a in alerts if a['severity'] in ('HIGH', 'CRITICAL') or a.get('risk_score', 0) > 60]
    if not high_alerts:
        pdf.cell(200, 10, "No high-severity threats or critical risks detected.", ln=True)
    else:
        for a in high_alerts[:25]:  # Top 25
            pdf.cell(200, 8, f"[{a['time']}] {a['type']} (Risk: {a.get('risk_score', 0)}/100 | ML: {a.get('ml_prediction', 'N/A')})", ln=True)
            pdf.cell(200, 6, f"   Source: {a.get('src', 'Unknown')} -> Dest: {a.get('dst', 'Unknown')} ({a.get('proto', 'Unknown')})", ln=True)
            pdf.cell(200, 6, f"   Detail: {a['detail']} (Anomaly: {a.get('anomaly_score', 0.0)})", ln=True)
            pdf.cell(200, 6, f"   Action Taken: {a.get('action_taken', a.get('mitigation', 'None'))}", ln=True)
            pdf.ln(2)
            
    return bytes(pdf.output())
