import logging
from .base_provider import BaseNotificationProvider

log = logging.getLogger("watchman.notifications.webhook")

class WebhookProvider(BaseNotificationProvider):
    def send(self, incident: dict) -> bool:
        # In a real environment, we'd use requests.post(url, json=payload)
        # For demonstration purposes, we'll log the webhook dispatch.
        try:
            log.info(f"[WEBHOOK SENT] Discord/Slack Hook Triggered")
            log.info(f"Payload: {incident.get('risk_level')} - {incident.get('threat')} from {incident.get('src')}")
            return True
        except Exception as e:
            log.error(f"Failed to trigger webhook: {e}")
            return False
