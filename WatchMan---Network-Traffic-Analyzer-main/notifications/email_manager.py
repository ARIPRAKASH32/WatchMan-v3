"""
notifications/email_manager.py — Reusable OOP Gmail Alert System.

Features:
  - Thread-safe design (`threading.RLock`)
  - Secure credential loading from `.env` via `python-dotenv` / `os.getenv`
  - Strict error handling (Authentication failed, timeout, network error, invalid address)
  - Automatic SQLite audit logging to `email_logs` table
  - Exact formatting for Critical Security Alerts and Test Emails
"""

import os
import time
import socket
import logging
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
import yaml
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv

from models.database import insert_email_log

# Load environment variables from .env if present
load_dotenv()

log = logging.getLogger("watchman.email_manager")
CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


class EmailManager:
    """
    Production-ready Email Manager adhering to clean OOP principles.
    Handles secure authentication, SMTP connection management, exact alert formatting,
    and comprehensive error reporting/logging.
    """
    def __init__(self):
        self._lock = threading.RLock()
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.use_tls = True
        self.username = "ariprakash32@gmail.com"
        self.password = ""
        self.recipient = "ariprakash32@gmail.com"
        self._load_credentials(force=True)

    def _load_credentials(self, force=False):
        """Load Gmail SMTP credentials securely from .env or config.yaml fallback."""
        with self._lock:
            # If we already have a valid runtime password and force is False, don't overwrite
            if not force and self.password and self.password not in ("YOUR_GMAIL_APP_PASSWORD", "secure_password"):
                return

            # First prioritize .env environment variables
            self.smtp_server = os.getenv("SMTP_SERVER", self.smtp_server)
            self.smtp_port = int(os.getenv("SMTP_PORT", self.smtp_port))
            self.use_tls = True
            
            env_user = os.getenv("EMAIL_USERNAME")
            if env_user:
                self.username = env_user
            env_pwd = os.getenv("EMAIL_PASSWORD")
            if env_pwd:
                self.password = env_pwd
            env_rec = os.getenv("EMAIL_RECIPIENT")
            if env_rec:
                self.recipient = env_rec

            # Fallback to config.yaml if environment variables are not set or defaults used
            if CONFIG_PATH.exists():
                try:
                    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                        cfg = yaml.safe_load(f) or {}
                        email_cfg = cfg.get("email", {})
                        if not self.password or self.password == "YOUR_GMAIL_APP_PASSWORD":
                            yaml_pwd = email_cfg.get("password")
                            if yaml_pwd and yaml_pwd not in ("secure_password", "YOUR_GMAIL_APP_PASSWORD"):
                                self.password = yaml_pwd
                        if not os.getenv("EMAIL_USERNAME"):
                            yaml_user = email_cfg.get("username")
                            if yaml_user and yaml_user != "user@example.com":
                                self.username = yaml_user
                        if not os.getenv("EMAIL_RECIPIENT"):
                            yaml_to = email_cfg.get("to_address")
                            if yaml_to and yaml_to != "admin@example.com":
                                self.recipient = yaml_to
                except Exception as e:
                    log.warning("Could not load email configuration from config.yaml: %s", e)

    def reload_settings(self, smtp_server=None, smtp_port=None, username=None, password=None, recipient=None):
        """Dynamically update runtime settings (used by Settings UI)."""
        with self._lock:
            if smtp_server:
                self.smtp_server = smtp_server
            if smtp_port:
                self.smtp_port = int(smtp_port)
            if username:
                self.username = username
            if password and password != "********":
                self.password = password
            if recipient:
                self.recipient = recipient

    def send_email(self, subject: str, body: str, recipient: str = None) -> tuple[bool, str]:
        """
        Base method to send a plain-text email via Gmail SMTP with complete error handling and SQLite logging.
        Returns tuple: (success: bool, message: str).
        """
        with self._lock:
            self._load_credentials(force=False)
            target_recipient = recipient or self.recipient or self.username

            if not target_recipient or target_recipient == "Unknown":
                error_msg = "Invalid Email Address: No valid recipient specified."
                log.error(error_msg)
                insert_email_log({
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "recipient": target_recipient,
                    "subject": subject,
                    "status": "FAILED",
                    "error_message": error_msg
                })
                return False, error_msg

            if not self.password or self.password in ("YOUR_GMAIL_APP_PASSWORD", "secure_password"):
                error_msg = "Wrong App Password / Credentials Missing: Please set your 16-character Gmail App Password in .env or Settings."
                log.error(error_msg)
                insert_email_log({
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "recipient": target_recipient,
                    "subject": subject,
                    "status": "FAILED",
                    "error_message": error_msg
                })
                return False, error_msg

            try:
                msg = MIMEMultipart()
                msg["From"] = self.username
                msg["To"] = target_recipient
                msg["Subject"] = subject
                msg.attach(MIMEText(body, "plain", "utf-8"))

                log.info("Connecting to SMTP Server %s:%s...", self.smtp_server, self.smtp_port)
                with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=12) as server:
                    if self.use_tls:
                        server.starttls()
                    server.login(self.username, self.password)
                    server.send_message(msg)

                success_msg = f"Email successfully sent via Gmail SMTP to {target_recipient}"
                log.info(success_msg)
                insert_email_log({
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "recipient": target_recipient,
                    "subject": subject,
                    "status": "SUCCESS",
                    "error_message": ""
                })
                return True, success_msg

            except smtplib.SMTPAuthenticationError as e:
                error_msg = f"SMTP Authentication Failed: Wrong username or Gmail App Password ({e.smtp_error.decode('utf-8', 'ignore') if hasattr(e.smtp_error, 'decode') else str(e)})"
                log.error(error_msg)
            except smtplib.SMTPRecipientsRefused as e:
                error_msg = f"Invalid Email Address: Recipient address rejected ({str(e)})"
                log.error(error_msg)
            except (smtplib.SMTPConnectError, TimeoutError, socket.timeout) as e:
                error_msg = f"SMTP Timeout / Connection Error: Could not connect to {self.smtp_server}:{self.smtp_port} ({str(e)})"
                log.error(error_msg)
            except (socket.gaierror, socket.error) as e:
                error_msg = f"Internet Not Available / DNS Error: Unable to reach destination server ({str(e)})"
                log.error(error_msg)
            except Exception as e:
                error_msg = f"Unexpected SMTP Error: {str(e)}"
                log.error(error_msg)

            insert_email_log({
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "recipient": target_recipient,
                "subject": subject,
                "status": "FAILED",
                "error_message": error_msg
            })
            return False, error_msg

    def send_critical_alert(self, incident: dict) -> tuple[bool, str]:
        """
        Send a critical security alert email formatted exactly as specified by the requirements.
        Triggered when Risk Score >= 80 or Threat Level == CRITICAL.
        """
        subject = "🚨 WATCH MAN - Critical Security Alert"

        # Extract incident details safely with clean fallbacks
        attack_type = incident.get("type", incident.get("threat", "Unknown Attack"))
        risk_score = int(incident.get("risk_score", 0))
        risk_level = incident.get("risk_level", incident.get("severity", "CRITICAL")).upper()
        src_ip = incident.get("src", "Unknown")
        dst_ip = incident.get("dst", "Unknown")
        protocol = incident.get("proto", "TCP")
        packet_size = incident.get("size", incident.get("packet_size", 1500))
        ml_prediction = incident.get("ml_prediction", attack_type)
        anomaly_score = float(incident.get("anomaly_score", 0.0))
        detection_time = incident.get("time", time.strftime("%Y-%m-%d %I:%M %p"))

        # Parse and format recommended actions cleanly with checkmarks
        raw_mitigation = incident.get("mitigation", incident.get("recommendations", ""))
        actions_list = []
        if isinstance(raw_mitigation, list):
            actions_list = raw_mitigation
        elif isinstance(raw_mitigation, str) and raw_mitigation:
            # Split by line or common bullet separators
            lines = [l.strip("- ✔*• ").strip() for l in raw_mitigation.split("\n") if l.strip("- ✔*• ").strip()]
            actions_list = lines if lines else ["Block Source IP", "Enable Firewall", "Monitor Network", "Investigate Logs"]
        else:
            actions_list = ["Block Source IP", "Enable Firewall", "Monitor Network", "Investigate Logs"]

        actions_formatted = "\n\n".join([f"✔ {act}" for act in actions_list])

        # Exact body layout
        body = f"""WATCH MAN - AI Intrusion Detection Alert

Attack Type:
{attack_type}

Risk Score:
{risk_score}/100

Risk Level:
{risk_level}

Source IP:
{src_ip}

Destination IP:
{dst_ip}

Protocol:
{protocol}

Packet Size:
{packet_size} Bytes

ML Prediction:
{ml_prediction}

Anomaly Score:
{anomaly_score:.2f}

Detection Time:
{detection_time}

Recommended Actions

{actions_formatted}

--------------------------------------------------

This email was automatically generated by

Watch Man AI-Powered Intrusion Detection & Response System."""

        return self.send_email(subject, body)

    def send_test_email(self, recipient: str = None) -> tuple[bool, str]:
        """
        Send the exact required verification test email to confirm Gmail SMTP configuration.
        """
        subject = "✅ WATCH MAN Test Email"
        body = (
            "This is a test email from the Watch Man AI-Powered Intrusion Detection & Response System.\n\n"
            "If you received this email successfully, Gmail SMTP has been configured correctly."
        )
        return self.send_email(subject, body, recipient=recipient)

    def get_status(self) -> dict:
        """
        Return current configuration status for the UI/API, masking the password.
        """
        with self._lock:
            self._load_credentials()
            is_configured = bool(self.username and self.password and self.password not in ("YOUR_GMAIL_APP_PASSWORD", "secure_password"))
            masked_password = "********" if is_configured else ""
            return {
                "smtp_server": self.smtp_server,
                "smtp_port": self.smtp_port,
                "use_tls": self.use_tls,
                "sender_email": self.username,
                "recipient_email": self.recipient,
                "password_masked": masked_password,
                "is_configured": is_configured
            }


# Singleton instance
email_manager = EmailManager()
