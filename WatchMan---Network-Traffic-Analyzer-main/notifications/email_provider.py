import logging
from .base_provider import BaseNotificationProvider
from .email_manager import email_manager

log = logging.getLogger("watchman.notifications.email")

class EmailProvider(BaseNotificationProvider):
    def send(self, incident: dict) -> bool:
        """Delegate incident notification directly to the production-ready EmailManager."""
        try:
            success, message = email_manager.send_critical_alert(incident)
            if success:
                log.info(f"[EMAIL NOTIFICATION SENT] {message}")
            else:
                log.warning(f"[EMAIL NOTIFICATION FAILED] {message}")
            return success
        except Exception as e:
            log.error(f"Error executing EmailProvider.send: {e}")
            return False
