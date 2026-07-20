import os
import json
import time
import logging
import uuid
from notifications.email_provider import EmailProvider
from notifications.webhook_provider import WebhookProvider

log = logging.getLogger("watchman.incident_reporter")

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
REPORTS_DIR = os.path.join(LOG_DIR, "reports")
EVIDENCE_DIR = os.path.join(LOG_DIR, "evidence")

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(EVIDENCE_DIR, exist_ok=True)

class IncidentReporter:
    def __init__(self, risk_rules):
        self.risk_rules = risk_rules
        self.email_provider = EmailProvider()
        self.webhook_provider = WebhookProvider()
        
    def handle_incident(self, incident: dict):
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        incident["id"] = incident_id
        
        score = incident.get("risk_score", 0)
        
        # Save evidence for HIGH and CRITICAL (Score > 60)
        if score > self.risk_rules.get("response_thresholds", {}).get("medium", 60):
            self._save_evidence(incident)
            
        # Generate Reports for HIGH and CRITICAL (Score > 80)
        if score > self.risk_rules.get("notifications", {}).get("report_threshold", 80):
            self._generate_report(incident)
            
        # Send Notifications
        if self.risk_rules.get("notifications", {}).get("enabled", True):
            if score > self.risk_rules.get("notifications", {}).get("email_threshold", 60):
                self.email_provider.send(incident)
            if score > self.risk_rules.get("notifications", {}).get("webhook_threshold", 60):
                self.webhook_provider.send(incident)
                
        return incident

    def _save_evidence(self, incident: dict):
        incident_id = incident["id"]
        evidence_path = os.path.join(EVIDENCE_DIR, f"{incident_id}_evidence.json")
        try:
            # Emulating saving PCAP, flow stats, etc by saving enriched metadata
            evidence_data = {
                "incident": incident,
                "flow_statistics": "Extracted flow stats placeholder",
                "network_metadata": "Metadata placeholder"
            }
            with open(evidence_path, "w") as f:
                json.dump(evidence_data, f, indent=2)
            log.info(f"Evidence collected and preserved for {incident_id}")
        except Exception as e:
            log.error(f"Failed to save evidence for {incident_id}: {e}")

    def _generate_report(self, incident: dict):
        incident_id = incident["id"]
        json_path = os.path.join(REPORTS_DIR, f"{incident_id}.json")
        md_path = os.path.join(REPORTS_DIR, f"{incident_id}.md")
        
        try:
            # JSON
            with open(json_path, "w") as f:
                json.dump(incident, f, indent=2)
                
            # Markdown Report
            md_content = f"""# Incident Report: {incident_id}
**Detection Timestamp:** {incident.get('time')}
**Threat Type:** {incident.get('threat')}
**Risk Score:** {incident.get('risk_score')} ({incident.get('risk_level')})

## AI Intelligence
**Confidence:** {incident.get('ai_confidence')}%
**AI Explanation:**
{incident.get('ai_explanation')}

## Indicators of Compromise (IOCs)
- **Source IP:** {incident.get('src')}
- **Destination IP:** {incident.get('dst')}
- **Protocol:** {incident.get('proto')}

## Recommended Actions
{incident.get('mitigation')}

*Generated automatically by Watch Man AI Risk Assessment Engine*
"""
            with open(md_path, "w") as f:
                f.write(md_content)
                
            log.info(f"Incident report generated for {incident_id}")
        except Exception as e:
            log.error(f"Failed to generate report for {incident_id}: {e}")
