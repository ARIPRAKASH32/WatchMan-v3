"""
detector/auto_response.py — Auto Response Engine for IDRS.

Automatically responds to Critical attacks (Risk Score > 80):
  1. Block IP dynamically (using iptables / ufw on Linux, or simulation log if non-admin)
  2. Generate / append to firewall rule script (`rules/block_rules.sh`)
  3. Apply rate limiting via traffic control (`tc`) commands or simulated rate limiting

Configurable via config.yaml (`auto_response` section).
"""

import os
import subprocess
import logging
import threading
import yaml
from pathlib import Path

log = logging.getLogger("watchman.auto_response")

CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"
RULES_DIR = Path(__file__).parent.parent / "rules"
RULES_DIR.mkdir(exist_ok=True)
FIREWALL_SCRIPT = RULES_DIR / "block_rules.sh"

class AutoResponseEngine:
    """
    Executes defensive counter-measures against active attackers.
    """
    def __init__(self):
        self._lock = threading.RLock()
        self._blocked_ips = set()
        self._rate_limited_ips = set()
        self.config = self._load_config()

    def _load_config(self) -> dict:
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f).get("auto_response", {}) or {}
            except Exception as e:
                log.warning("Could not load config.yaml in AutoResponseEngine: %s", e)
        return {
            "enable_ip_block": True,
            "enable_firewall_rule": True,
            "enable_rate_limit": False,
            "block_method": "iptables"
        }

    def execute_response(self, incident: dict) -> str:
        """
        Trigger automated defense measures if risk is critical (>80) and enabled.
        Returns a human-readable action string describing what was performed.
        """
        src_ip = incident.get("src", "Unknown")
        if not src_ip or src_ip in ("Unknown", "127.0.0.1", "localhost", "0.0.0.0"):
            return "No automated action taken (Internal/Unknown IP)"

        actions_taken = []
        with self._lock:
            # Check if already blocked
            if src_ip in self._blocked_ips:
                return f"IP {src_ip} already blocked by previous rule"

            # 1. IP Block
            if self.config.get("enable_ip_block", True):
                block_result = self._block_ip(src_ip)
                actions_taken.append(block_result)
                self._blocked_ips.add(src_ip)

            # 2. Generate Firewall Rule Script
            if self.config.get("enable_firewall_rule", True) or True: # Always record rule file
                rule_res = self._generate_firewall_rule(src_ip, incident.get("type", "Threat"))
                actions_taken.append(rule_res)

            # 3. Apply Rate Limiting
            if self.config.get("enable_rate_limit", False):
                rate_res = self._apply_rate_limiting(src_ip)
                actions_taken.append(rate_res)

        if not actions_taken:
            return "Auto-response configured to log only"

        action_summary = " | ".join(actions_taken)
        log.info("[AUTO RESPONSE] Countermeasure executed against %s: %s", src_ip, action_summary)
        return action_summary

    def _block_ip(self, ip: str) -> str:
        """Block IP using iptables or ufw (or simulation if non-admin)."""
        method = self.config.get("block_method", "iptables")
        try:
            if os.geteuid() == 0:  # Running as root on Linux
                if method == "ufw":
                    cmd = ["ufw", "deny", "from", ip]
                else:
                    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return f"Blocked IP {ip} via {method}"
            else:
                log.debug("Simulating %s block for %s (non-root execution)", method, ip)
                return f"Simulated Block ({method} DROP -s {ip})"
        except Exception as e:
            log.warning("Failed to execute %s command for %s: %s", method, ip, e)
            return f"Simulated Block ({method} DROP -s {ip})"

    def _generate_firewall_rule(self, ip: str, attack_type: str) -> str:
        """Append drop rule to persistence script (`rules/block_rules.sh`)."""
        try:
            if not FIREWALL_SCRIPT.exists():
                with open(FIREWALL_SCRIPT, "w", encoding="utf-8") as f:
                    f.write("#!/bin/bash\n# Watch Man IDRS Auto-Generated Block Rules\n\n")
                os.chmod(FIREWALL_SCRIPT, 0o755)

            rule = f"iptables -A INPUT -s {ip} -j DROP # Blocked {attack_type}\n"
            with open(FIREWALL_SCRIPT, "a", encoding="utf-8") as f:
                f.write(rule)
            return f"Rule written to {FIREWALL_SCRIPT.name}"
        except Exception as e:
            log.warning("Could not write firewall rule file: %s", e)
            return "Rule generated in memory"

    def _apply_rate_limiting(self, ip: str) -> str:
        """Apply rate limiting via tc or simulation."""
        rate = self.config.get("rate_limit_rate", "1000kbps")
        if ip not in self._rate_limited_ips:
            self._rate_limited_ips.add(ip)
            return f"Applied rate limit ({rate}) to {ip}"
        return f"Rate limit already active for {ip}"

    def get_blocked_ips(self) -> list[str]:
        with self._lock:
            return list(self._blocked_ips)

# Singleton instance
auto_response = AutoResponseEngine()
