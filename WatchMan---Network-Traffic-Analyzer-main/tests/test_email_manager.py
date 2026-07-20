import unittest
from unittest.mock import patch, MagicMock
import smtplib
from notifications.email_manager import EmailManager
from detector.alert_manager import AlertManager


class TestEmailManager(unittest.TestCase):
    def setUp(self):
        self.email_manager = EmailManager()
        self.email_manager.reload_settings(
            smtp_server="smtp.gmail.com",
            smtp_port=587,
            username="ariprakash32@gmail.com",
            password="TEST_APP_PASSWORD",
            recipient="ariprakash32@gmail.com"
        )

    @patch("smtplib.SMTP")
    def test_send_test_email(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        success, message = self.email_manager.send_test_email()
        self.assertTrue(success)
        self.assertIn("successfully sent", message)

        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("ariprakash32@gmail.com", "TEST_APP_PASSWORD")
        mock_server.send_message.assert_called_once()

        sent_msg = mock_server.send_message.call_args[0][0]
        self.assertEqual(sent_msg["Subject"], "✅ WATCH MAN Test Email")
        payload_text = sent_msg.get_payload()[0].get_payload(decode=True).decode("utf-8")
        self.assertIn("Gmail SMTP has been configured correctly", payload_text)

    @patch("smtplib.SMTP")
    def test_send_critical_alert_formatting(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        incident = {
            "type": "SYN Flood",
            "risk_score": 96,
            "risk_level": "CRITICAL",
            "src": "192.168.1.25",
            "dst": "192.168.1.1",
            "proto": "TCP",
            "size": 1500,
            "ml_prediction": "SYN Flood",
            "anomaly_score": 0.94,
            "time": "2026-07-16 10:45 PM",
            "mitigation": ["Block Source IP", "Enable Firewall", "Monitor Network", "Investigate Logs"]
        }

        success, message = self.email_manager.send_critical_alert(incident)
        self.assertTrue(success)

        sent_msg = mock_server.send_message.call_args[0][0]
        self.assertEqual(sent_msg["Subject"], "🚨 WATCH MAN - Critical Security Alert")
        
        body_text = sent_msg.get_payload()[0].get_payload(decode=True).decode("utf-8")
        self.assertIn("WATCH MAN - AI Intrusion Detection Alert", body_text)
        self.assertIn("Attack Type:\nSYN Flood", body_text)
        self.assertIn("Risk Score:\n96/100", body_text)
        self.assertIn("Risk Level:\nCRITICAL", body_text)
        self.assertIn("Source IP:\n192.168.1.25", body_text)
        self.assertIn("✔ Block Source IP", body_text)
        self.assertIn("✔ Enable Firewall", body_text)
        self.assertIn("Watch Man AI-Powered Intrusion Detection & Response System.", body_text)

    @patch("smtplib.SMTP")
    def test_smtp_error_handling_authentication_failed(self, mock_smtp_class):
        mock_smtp_class.return_value.__enter__.side_effect = smtplib.SMTPAuthenticationError(535, b"535 Authentication failed")

        success, message = self.email_manager.send_test_email()
        self.assertFalse(success)
        self.assertIn("SMTP Authentication Failed: Wrong username or Gmail App Password", message)


class TestAlertManagerThresholds(unittest.TestCase):
    def setUp(self):
        self.alert_mgr = AlertManager()
        self.alert_mgr.cooldown_seconds = 0  # disable cooldown for clean testing

    @patch("notifications.email_manager.email_manager.send_critical_alert")
    def test_process_and_dispatch_high_risk_score(self, mock_send):
        mock_send.return_value = (True, "Sent")
        incident = {"type": "SYN Flood", "risk_score": 85, "severity": "HIGH", "src": "10.0.0.1", "confidence": 95.0}
        
        res = self.alert_mgr.process_and_dispatch(incident)
        self.assertTrue(res["email_sent"])

    @patch("notifications.email_manager.email_manager.send_critical_alert")
    def test_process_and_dispatch_critical_threat_level(self, mock_send):
        mock_send.return_value = (True, "Sent")
        incident = {"type": "Exploit Attempt", "risk_score": 75, "severity": "CRITICAL", "src": "10.0.0.2", "confidence": 90.0}
        
        res = self.alert_mgr.process_and_dispatch(incident)
        self.assertTrue(res["email_sent"])

    @patch("notifications.email_manager.email_manager.send_critical_alert")
    def test_process_and_dispatch_below_threshold(self, mock_send):
        mock_send.return_value = (True, "Sent")
        incident = {"type": "Normal Traffic", "risk_score": 30, "severity": "LOW", "src": "10.0.0.3", "confidence": 90.0}
        
        res = self.alert_mgr.process_and_dispatch(incident)
        self.assertFalse(res["email_sent"])
        mock_send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
