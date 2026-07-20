import logging

log = logging.getLogger("watchman.notifications.base")

class BaseNotificationProvider:
    def __init__(self, config=None):
        self.config = config or {}
        
    def send(self, incident: dict) -> bool:
        """Send notification for the given incident. Returns True if successful."""
        raise NotImplementedError("Subclasses must implement send()")
