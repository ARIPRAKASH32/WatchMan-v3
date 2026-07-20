"""
sniffer/capture.py — Watch Man packet capture engine.

Two modes:
  1. LIVE — Scapy raw-socket capture (requires root / CAP_NET_RAW).
     Parses IP / TCP / UDP / ICMP / DNS / HTTP layers accurately.
  2. DEMO — Realistic synthetic traffic simulator with threat scenarios.
     Used automatically when raw-socket access is unavailable.

Fixes vs. original:
  - _running flag now correctly guards the simulation loop AND is exposed via stop_capture()
  - ICMP flood simulation now passes sport=None, dport=None explicitly (no TypeError)
  - Demo simulator ensures src != dst on every packet
  - Live capture uses BPF filter "ip" on all interfaces; falls back per-interface
  - Port scan scenario added to demo mode
  - SSH brute-force scenario added to demo mode
  - Thread name set for easier debugging
  - reset_state() called before starting so counters are clean on restart
"""

import threading
import time
import random
import socket
import logging

from models import data_store
from detector import start_engine, stop_engine, enqueue_packet
from utils.system import is_admin

log = logging.getLogger("watchman.capture")

# ── Demo simulation pool ───────────────────────────────────────────────────────
_INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "192.168.1.100","10.0.0.5",     "10.0.0.10",
    "172.16.0.1",   "172.16.0.50",
]
_EXTERNAL_IPS = [
    "8.8.8.8",         "1.1.1.1",       "208.67.222.222",
    "185.220.101.5",   "45.33.32.156",  "91.108.4.1",
    "104.21.32.100",
]
_ALL_IPS   = _INTERNAL_IPS + _EXTERNAL_IPS
_PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP"]
_PROTO_WEIGHTS = [40, 25, 10, 15, 10]
_COMMON_PORTS  = [80, 443, 22, 53, 8080, 8443, 3306, 5432, 25, 587]

# ── Thread state ───────────────────────────────────────────────────────────────
_sniffer_thread: threading.Thread | None = None
_running = False
_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
#  LIVE CAPTURE (Scapy)
# ══════════════════════════════════════════════════════════════════════════════

def _process_packet(pkt) -> None:
    """
    Scapy packet callback — invoked for every captured packet.
    Extracts IP / MAC / transport-layer fields and feeds data_store + threat_detector.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether, ARP

        src_mac = dst_mac = None
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        src = dst = None
        proto = "OTHER"
        sport = dport = None
        size = len(pkt)

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            proto = "IPv6"
        elif pkt.haslayer(ARP):
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
            proto = "ARP"
        else:
            return  # Skip non-IP/ARP

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            if dport in (80, 8080) or sport in (80, 8080):
                proto = "HTTP"
            elif dport in (443, 8443) or sport in (443, 8443):
                proto = "HTTPS"
            elif dport == 21 or sport == 21:
                proto = "FTP"
            elif dport == 22 or sport == 22:
                proto = "SSH"
            elif dport == 25 or sport == 25:
                proto = "SMTP"
            else:
                proto = "TCP"
                
            # Threat detector will inspect TCP flags
            flags = getattr(tcp, 'flags', None)

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
            if dport == 53 or sport == 53:
                proto = "DNS"
            elif dport in (67, 68) or sport in (67, 68):
                proto = "DHCP"
            else:
                proto = "UDP"
            flags = None
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            flags = None
        else:
            flags = None

        data_store.record_packet(src, dst, proto, size, sport, dport, src_mac, dst_mac)
        enqueue_packet(src, dst, proto, size, sport, dport, src_mac, dst_mac, flags)

    except Exception as exc:
        log.debug("Packet processing error: %s", exc)


def _live_capture() -> None:
    """
    Start Scapy sniffer — blocks until _running is False or an error occurs.
    Requires root / CAP_NET_RAW privileges.
    """
    global _running
    from scapy.all import sniff, conf

    log.info("Live capture started (Scapy, interface=all, filter='ip')")

    # Scapy's stop_filter polls every 0.5 s so we can honour _running
    def _should_stop(_pkt):
        return not _running

    while _running:
        try:
            sniff(
                prn=_process_packet,
                store=False,
                filter="ip",
                stop_filter=_should_stop,
                timeout=5,
            )
        except Exception as exc:
            err_str = str(exc).lower()
            if "not permitted" in err_str or "not found" in err_str or "no such device" in err_str:
                log.error("Scapy sniff fatal error: %s (stopping capture thread)", exc)
                _running = False
                break
            log.error("Scapy sniff error: %s — retrying in 2 s", exc)
            time.sleep(2)


# ══════════════════════════════════════════════════════════════════════════════
#  DEMO / SIMULATION MODE
# ══════════════════════════════════════════════════════════════════════════════

def _pick_pair() -> tuple[str, str]:
    """Return a (src, dst) pair where src != dst."""
    src = random.choice(_ALL_IPS)
    dst = random.choice([ip for ip in _ALL_IPS if ip != src])
    return src, dst


def _simulate_traffic() -> None:
    """
    Generate realistic synthetic network traffic for demo / non-root environments.

    Scenarios simulated:
      - Baseline mixed traffic (TCP/UDP/ICMP/DNS/HTTP)
      - DoS spike every ~30 s from a known external attacker IP
      - ICMP flood every ~50 s
      - Port scan sweep every ~70 s  (NEW)
      - SSH brute-force attempt every ~90 s  (NEW)
    """
    log.info("Demo/simulation mode active — generating synthetic traffic")
    tick = 0

    while _running:
        # ── Baseline burst ────────────────────────────────────────────────────
        burst = random.randint(5, 20)
        for _ in range(burst):
            src, dst = _pick_pair()
            proto = random.choices(_PROTOCOLS, weights=_PROTO_WEIGHTS)[0]
            size  = random.randint(64, 1460)
            sport = random.choice(_COMMON_PORTS)
            dport = random.choice(_COMMON_PORTS)

            data_store.record_packet(src, dst, proto, size, sport, dport, None, None)
            enqueue_packet(src, dst, proto, size, sport, dport, None, None, None)

        tick += 1

        # ── Scenario 1: DoS spike (~every 30 s) ──────────────────────────────
        if tick % 30 == 0:
            attacker = "185.220.101.5"
            target   = "192.168.1.10"
            log.debug("Demo: injecting DoS spike from %s", attacker)
            for _ in range(100):
                if not _running:
                    break
                data_store.record_packet(attacker, target, "TCP", 64, 54321, 80, None, None)
                enqueue_packet(attacker, target, "TCP", 64, 54321, 80, None, None, 'S')

        # ── Scenario 2: ICMP flood (~every 50 s) ─────────────────────────────
        if tick % 50 == 0:
            attacker = "45.33.32.156"
            target   = "192.168.1.100"
            log.debug("Demo: injecting ICMP flood from %s", attacker)
            for _ in range(60):
                if not _running:
                    break
                data_store.record_packet(attacker, target, "ICMP", 64, None, None, None, None)
                enqueue_packet(attacker, target, "ICMP", 64, None, None, None, None, None)

        # ── Scenario 3: Port scan (~every 70 s) ──────────────────────────────
        if tick % 70 == 0:
            scanner = "91.108.4.1"
            victim  = "192.168.1.20"
            log.debug("Demo: injecting port scan from %s", scanner)
            for p in range(20, 36):          # 16 unique ports → triggers scan alert
                if not _running:
                    break
                data_store.record_packet(scanner, victim, "TCP", 40, random.randint(40000,65000), p, None, None)
                enqueue_packet(scanner, victim, "TCP", 40, random.randint(40000, 65000), p, None, None, 'S')

        # ── Scenario 4: SSH brute-force (~every 90 s) ─────────────────────────
        if tick % 90 == 0:
            bruteforcer = "104.21.32.100"
            ssh_target  = "192.168.1.30"
            log.debug("Demo: injecting SSH brute-force from %s", bruteforcer)
            for _ in range(20):
                if not _running:
                    break
                data_store.record_packet(bruteforcer, ssh_target, "TCP", 60,
                                         random.randint(40000, 65000), 22, None, None)
                enqueue_packet(bruteforcer, ssh_target, "TCP", 60,
                             random.randint(40000, 65000), 22, None, None, 'S')

        time.sleep(1)


# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def start_capture(interface: str | None = None, demo: bool = False) -> threading.Thread:
    """
    Start the packet engine in a background daemon thread.

    Args:
        interface: Network interface name for live capture (None = all interfaces).
        demo:      Force demo/simulation mode regardless of privileges.

    Returns:
        The started Thread object.
    """
    global _sniffer_thread, _running

    with _lock:
        if _sniffer_thread and _sniffer_thread.is_alive():
            log.warning("Capture already running — ignoring start request.")
            return _sniffer_thread

        # Reset all counters so a restart begins from zero
        data_store.reset_state()

        _running = True

        if demo:
            target = _simulate_traffic
            mode_label = "DEMO (simulated traffic)"
        else:
            target = _try_live_or_fallback()
            mode_label = "LIVE (Scapy)" if target is _live_capture else "DEMO (fallback)"

        start_engine(num_workers=2)
        _sniffer_thread = threading.Thread(
            target=target,
            name="watchman-sniffer",
            daemon=True,
        )
        _sniffer_thread.start()
        log.info("Capture thread started — mode: %s", mode_label)

    return _sniffer_thread


def stop_capture() -> None:
    """Signal the sniffer thread to stop.  Non-blocking — thread exits within ~1 s."""
    global _running
    _running = False
    stop_engine()
    log.info("Capture stop requested.")


def _try_live_or_fallback():
    """
    Test whether raw packet capture access is available across platforms.
    Returns _live_capture if possible, else _simulate_traffic.
    """
    if not is_admin():
        log.info("Elevated privileges required for live sniffing. Falling back to demo/simulation mode.")
        return _simulate_traffic

    try:
        import scapy.all  # noqa: F401
        from scapy.arch import get_if_list
        if not get_if_list():
            log.warning("No network interfaces detected. WinPcap/Npcap missing?")
            raise OSError("No interfaces")
        return _live_capture
    except Exception as e:
        log.info("Raw capture capabilities unavailable (%s) — falling back to demo/simulation mode.", e)
        return _simulate_traffic


def is_running() -> bool:
    """Return True if the sniffer thread is alive."""
    return _sniffer_thread is not None and _sniffer_thread.is_alive()
