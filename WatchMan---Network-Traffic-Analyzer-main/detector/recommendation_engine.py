"""
detector/recommendation_engine.py — AI Recommendation Engine for IDRS.

After every detected attack or anomaly, generates detailed analysis:
  - Attack Type
  - Reason (Root cause / detection rationale)
  - Risk Score
  - Recommended Actions (step-by-step mitigation advice)
"""

import logging

log = logging.getLogger("watchman.recommendations")

class AIRecommendationEngine:
    """
    Produces actionable SOC recommendations and root-cause explanations for detected threats.
    """
    def __init__(self):
        self._templates = {
            "Port Scan": {
                "reason": "Rapid reconnaissance sweep detected targeting multiple distinct ports across a short duration. The attacker is probing open services to identify potential vulnerabilities.",
                "actions": [
                    "Block Source IP immediately at the perimeter firewall or router.",
                    "Enable strict firewall state tracking and drop unrequested SYN sweeps.",
                    "Audit server and close or restrict access to unused / management ports.",
                    "Monitor network traffic closely for secondary exploitation attempts on discovered services."
                ]
            },
            "DoS": {
                "reason": "High-velocity packet flood detected (SYN flood or HTTP volume surge) exceeding safe thresholds, aiming to exhaust server CPU or bandwidth resources.",
                "actions": [
                    "Enable SYN Cookies (`sysctl -w net.ipv4.tcp_syncookies=1`) and TCP rate limiting.",
                    "Apply upstream DDoS mitigation or rate limit the offending source IP (`iptables limit`).",
                    "Configure Web Application Firewall (WAF) challenge/challenge-response for high-frequency requests.",
                    "Verify connection backlog limits and scale backend infrastructure if needed."
                ]
            },
            "SSH Brute Force": {
                "reason": "Repeated high-frequency TCP connection attempts targeting port 22 (SSH). The attacker is attempting automated dictionary or credential guessing attacks.",
                "actions": [
                    "Immediately block the source IP or install/enable Fail2Ban or DenyHosts.",
                    "Disable password authentication on SSH and mandate SSH RSA/ED25519 key-based logins only.",
                    "Change SSH listening port to a non-standard port or restrict SSH access via VPN/Allowlist.",
                    "Inspect system authentication logs (`/var/log/auth.log` or `/var/log/secure`) for successful logins."
                ]
            },
            "DNS Attack": {
                "reason": "Abnormal volume of DNS requests/responses or oversized UDP packet payloads on port 53 indicating a DNS Amplification/Reflection attack or tunneling.",
                "actions": [
                    "Disable recursion on authoritative DNS servers to prevent amplification abuse.",
                    "Implement Response Rate Limiting (RRL) on DNS servers.",
                    "Inspect DNS query payloads for unauthorized tunneling or exfiltration domains.",
                    "Filter out-of-state UDP traffic at the firewall."
                ]
            },
            "ARP Spoofing": {
                "reason": "Conflicting ARP replies observed where a single MAC address claims multiple IP addresses or impersonates the default gateway (Man-in-the-Middle attempt).",
                "actions": [
                    "Configure Static ARP entries for critical network gateways (`arp -s`).",
                    "Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on managed network switches.",
                    "Isolate the offending host device from the local area network immediately.",
                    "Verify SSL/TLS certificate integrity across active client sessions."
                ]
            },
            "Unknown Attack": {
                "reason": "Isolation Forest anomaly detector identified highly irregular traffic patterns (abnormal protocol flags, payload sizes, or inter-arrival rates) deviating from normal baseline.",
                "actions": [
                    "Capture full packet payload (PCAP) for deep forensic inspection.",
                    "Isolate the affected internal host or quarantine the external IP.",
                    "Review active endpoint processes and network connections on destination host.",
                    "Update IDS/IPS rule signatures to classify this emerging threat pattern."
                ]
            }
        }

    def get_recommendations(self, attack_type: str, risk_score: int, detail: str = "") -> dict:
        """
        Generate recommendation card for an attack.

        Returns:
            Dictionary with 'attack_type', 'reason', 'risk_score', and 'recommended_actions'.
        """
        # Match template or fallback to Unknown Attack
        template = self._templates.get(attack_type)
        if not template:
            # Check partial match (e.g., 'SYN Flood' -> 'DoS')
            if "flood" in attack_type.lower() or "dos" in attack_type.lower():
                template = self._templates["DoS"]
            elif "scan" in attack_type.lower():
                template = self._templates["Port Scan"]
            elif "brute" in attack_type.lower() or "ssh" in attack_type.lower():
                template = self._templates["SSH Brute Force"]
            elif "dns" in attack_type.lower():
                template = self._templates["DNS Attack"]
            elif "arp" in attack_type.lower():
                template = self._templates["ARP Spoofing"]
            else:
                template = self._templates["Unknown Attack"]

        reason = template["reason"]
        if detail and len(detail) > 5:
            reason = f"{detail}. {reason}"

        return {
            "attack_type": attack_type,
            "reason": reason,
            "risk_score": risk_score,
            "recommended_actions": list(template["actions"])
        }

# Singleton instance
recommendation_engine = AIRecommendationEngine()
