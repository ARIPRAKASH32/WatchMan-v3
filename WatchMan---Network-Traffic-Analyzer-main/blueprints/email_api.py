"""
blueprints/email_api.py — Flask Blueprint for Gmail Alert System & Settings API.

Endpoints:
  POST /test-email          — Send verification test email
  POST /send-alert          — Send critical alert email manually or via API
  GET  /email-status        — Get configuration status and recent audit logs
  POST /api/settings/email  — Update runtime SMTP/Gmail credentials
"""

import logging
# pyrefly: ignore [missing-import]
from flask import Blueprint, request, jsonify
from notifications.email_manager import email_manager
from models.database import get_email_logs

log = logging.getLogger("watchman.blueprints.email")

email_bp = Blueprint("email_api", __name__)


@email_bp.route("/test-email", methods=["POST"])
def test_email():
    """Trigger the verified verification test email."""
    data = request.get_json(silent=True) or {}
    recipient = data.get("recipient")
    success, message = email_manager.send_test_email(recipient=recipient)
    status_code = 200 if success else 400
    return jsonify({
        "success": success,
        "message": message
    }), status_code


@email_bp.route("/send-alert", methods=["POST"])
def send_alert():
    """Trigger a critical security alert email for a provided incident payload."""
    incident = request.get_json(silent=True) or {}
    if not incident:
        return jsonify({"success": False, "message": "No incident payload provided."}), 400
        
    success, message = email_manager.send_critical_alert(incident)
    status_code = 200 if success else 400
    return jsonify({
        "success": success,
        "message": message
    }), status_code


@email_bp.route("/email-status", methods=["GET"])
def email_status():
    """Return runtime configuration status, masked credentials, and historical audit logs."""
    status_data = email_manager.get_status()
    logs = get_email_logs(limit=50)
    return jsonify({
        "status": status_data,
        "audit_logs": logs
    }), 200


@email_bp.route("/api/settings/email", methods=["POST"])
def update_email_settings():
    """Update runtime SMTP/Gmail parameters safely."""
    data = request.get_json(silent=True) or {}
    smtp_server = data.get("smtp_server")
    smtp_port = data.get("smtp_port")
    username = data.get("sender_email")
    password = data.get("password")
    recipient = data.get("recipient_email")

    email_manager.reload_settings(
        smtp_server=smtp_server,
        smtp_port=smtp_port,
        username=username,
        password=password,
        recipient=recipient
    )
    log.info("Email settings updated dynamically via API.")
    return jsonify({
        "success": True,
        "message": "Email configuration updated and reloaded securely."
    }), 200
