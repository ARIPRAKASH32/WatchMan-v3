"""
detector/alert_manager.py — Alert Automation & Security Throttling Engine.

Handles automated notifications when:
  - Risk Score >= 80 OR Threat Level == CRITICAL
  - Dispatches Gmail SMTP alert via EmailManager
  - Triggers incident persistence

Includes strict security safeguards against:
  - Duplicate Alerts (Deduplication within configurable sliding window)
  - False Positives (Minimum confidence thresholds & anomaly confirmation)
  - Alert Flooding (Rate limiting per source/attack pair)
"""

import time
import logging
import threading
import yaml
from pathlib import Path
from notifications.email_manager import email_manager

log = logging.getLogger("watchman.alert_manager")
CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


class AlertManager:
    """
    Manages automated alert dispatch and throttles noisy/duplicate notifications.
    Uses Gmail SMTP for notifications; all Twilio functionality removed.
    """
    def __init__(self):
        self._lock = threading.RLock()
        # Track recent notifications: key = (attack_type, src_ip) -> timestamp
        self._sent_history = {}
        # Cooldown window in seconds before alerting on the exact same attack from same IP again
        self.cooldown_seconds = 300
        self.config = self._load_config()

    def _load_config(self) -> dict:
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                log.warning("Could not load config.yaml in AlertManager: %s", e)
        return {}

    def should_suppress(self, alert_type: str, src_ip: str, risk_score: int, confidence: float) -> tuple[bool, str]:
        """
        Evaluate anti-flooding and false-positive prevention rules.
        Returns (is_suppressed, reason_string).
        """
        now = time.time()
        with self._lock:
            # 1. False positive mitigation: ignore low confidence predictions unless rule-based risk is extreme
            if confidence < 65.0 and risk_score < 80:
                return True, f"Confidence {confidence}% too low (threshold 65%)"

            # 2. Duplicate / Flood suppression
            key = (alert_type, src_ip)
            last_sent = self._sent_history.get(key, 0)
            if now - last_sent < self.cooldown_seconds:
                return True, f"In cooldown window ({int(now - last_sent)}s / {self.cooldown_seconds}s)"

            # Record dispatch attempt
            self._sent_history[key] = now

            # Clean old history entries periodically
            if len(self._sent_history) > 1000:
                expired = [k for k, ts in self._sent_history.items() if now - ts > self.cooldown_seconds]
                for k in expired:
                    del self._sent_history[k]

        return False, "Not suppressed"

    def process_and_dispatch(
        self,
        incident: dict
    ) -> dict:
        """
        Evaluate an incident and dispatch automated Gmail email alerts whenever:
          Risk Score >= 80 OR Threat Level == CRITICAL.
        Returns a dict summarizing actions taken.
        """
        risk_score = incident.get("risk_score", 0)
        risk_level = incident.get("risk_level", incident.get("severity", "LOW")).upper()
        alert_type = incident.get("type", "Unknown Attack")
        src_ip = incident.get("src", "Unknown")
        confidence = incident.get("confidence", 85.0)

        results = {
            "suppressed": False,
            "email_sent": False,
            "reason": ""
        }

        # Check if condition is met: Risk Score >= 80 OR Threat Level == CRITICAL
        is_critical_condition = (risk_score >= 80) or (risk_level == "CRITICAL")

        # Check suppression if condition is not met or for rate limiting
        suppressed, reason = self.should_suppress(alert_type, src_ip, risk_score, confidence)
        if suppressed and not is_critical_condition:
            results["suppressed"] = True
            results["reason"] = reason
            return results

        if is_critical_condition:
            if suppressed:
                log.info("[ALERT MANAGER] Critical threat (%s from %s) throttled for external email dispatch: %s",
                         alert_type, src_ip, reason)
                results["suppressed"] = True
                results["reason"] = reason
                return results

            log.warning("[ALERT MANAGER] CRITICAL THREAT DETECTED (Risk Score %s | Level %s). Dispatching Gmail alert!",
                        risk_score, risk_level)
            
            # Dispatch email notification in background thread to avoid blocking packet capture loop
            threading.Thread(target=self._send_email_async, args=(incident,), daemon=True).start()
            results["email_sent"] = True

        return results

    def _send_email_async(self, incident: dict):
        """Send email alert asynchronously via EmailManager."""
        try:
            success, message = email_manager.send_critical_alert(incident)
            if success:
                log.info("Automated critical alert email delivered successfully.")
            else:
                log.warning("Automated critical alert email delivery failed: %s", message)
        except Exception as e:
            log.error("Exception in _send_email_async: %s", e)


# Singleton instance
alert_manager = AlertManager()
