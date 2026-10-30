"""
=============================================================================
NetShield: Network Packet Analyzer & Security Monitoring Dashboard
=============================================================================
Author: Senior Cybersecurity Engineer & Python Developer
Tech Stack: Python 3.10+, Scapy, Streamlit, Pandas, Plotly
Architecture: Thread-safe rolling buffer, multi-mode capture (Live/PCAP/Synthetic),
              stateful sliding-window anomaly detection engine.
=============================================================================
"""

import os
import sys
import time
import socket
import struct
import binascii
import threading
from datetime import datetime
from collections import deque, Counter
from typing import Dict, List, Optional, Tuple, Any

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# ---------------------------------------------------------------------------
# Scapy Imports with Fallback Handling
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        sniff, rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw,
        conf, get_if_list, Ether
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Streamlit Page Configuration & SOC Styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="NetShield | Network Packet Analyzer & Security Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber SOC Aesthetic CSS
st.markdown("""
<style>
    /* Metric Card Styling */
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(30, 41, 59, 0.7) 100%);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 10px;
        padding: 14px 18px;
        box-shadow: 0 4px 14px 0 rgba(0, 0, 0, 0.25);
    }
    div[data-testid="stMetric"]:hover {
        border-color: rgba(56, 189, 248, 0.5);
        transition: border-color 0.3s ease;
    }
    div[data-testid="stMetricLabel"] {
        font-size: 0.85rem !important;
        font-weight: 600 !important;
        color: #94a3b8 !important;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }
    div[data-testid="stMetricValue"] {
        font-size: 1.85rem !important;
        font-weight: 700 !important;
        color: #f8fafc !important;
    }
    
    /* Security Alert Card Styling */
    .alert-card-critical {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(185, 28, 28, 0.25) 100%);
        border-left: 5px solid #ef4444;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 12px;
    }
    .alert-card-high {
        background: linear-gradient(135deg, rgba(249, 115, 22, 0.15) 0%, rgba(194, 65, 12, 0.25) 100%);
        border-left: 5px solid #f97316;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 12px;
    }
    .alert-card-medium {
        background: linear-gradient(135deg, rgba(234, 179, 8, 0.15) 0%, rgba(161, 98, 7, 0.25) 100%);
        border-left: 5px solid #eab308;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 12px;
    }
    .alert-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: bold;
        letter-spacing: 0.05em;
        margin-right: 8px;
    }
    .badge-critical { background-color: #ef4444; color: #ffffff; }
    .badge-high { background-color: #f97316; color: #ffffff; }
    .badge-medium { background-color: #eab308; color: #1e293b; }
    .badge-info { background-color: #38bdf8; color: #0f172a; }

    /* Status Pills */
    .status-pill {
        display: inline-flex;
        align-items: center;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.82rem;
        font-weight: 600;
    }
    .status-running {
        background-color: rgba(34, 197, 94, 0.18);
        color: #4ade80;
        border: 1px solid rgba(34, 197, 94, 0.35);
    }
    .status-stopped {
        background-color: rgba(148, 163, 184, 0.18);
        color: #94a3b8;
        border: 1px solid rgba(148, 163, 184, 0.35);
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Constants & Well-Known Port Mappings
# ---------------------------------------------------------------------------
WELL_KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-Data", 21: "FTP-Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-Submission",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch"
}

# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------
class PacketRecord:
    """Represents a normalized, enriched network packet."""
    def __init__(
        self,
        index: int,
        timestamp: str,
        epoch: float,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        service: str,
        length: int,
        flags: str,
        info: str,
        is_suspicious: bool = False,
        alert_tags: Optional[List[str]] = None,
        hex_dump: str = ""
    ):
        self.index = index
        self.timestamp = timestamp
        self.epoch = epoch
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.service = service
        self.length = length
        self.flags = flags
        self.info = info
        self.is_suspicious = is_suspicious
        self.alert_tags = alert_tags or []
        self.hex_dump = hex_dump

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ID": self.index,
            "Timestamp": self.timestamp,
            "Source IP": self.src_ip,
            "Destination IP": self.dst_ip,
            "Protocol": self.protocol,
            "Src Port": self.src_port if self.src_port is not None else "-",
            "Dst Port": self.dst_port if self.dst_port is not None else "-",
            "Service": self.service,
            "Length (Bytes)": self.length,
            "TCP Flags": self.flags if self.flags else "-",
            "Info": self.info,
            "Suspicious": "⚠️ Yes" if self.is_suspicious else "No"
        }


class SecurityAlert:
    """Represents an anomaly or threat detected by the rule engine."""
    def __init__(
        self,
        alert_id: int,
        timestamp: str,
        epoch: float,
        severity: str,
        category: str,
        src_ip: str,
        target: str,
        description: str,
        mitre_ref: str,
        recommendation: str
    ):
        self.alert_id = alert_id
        self.timestamp = timestamp
        self.epoch = epoch
        self.severity = severity        # CRITICAL, HIGH, MEDIUM, INFO
        self.category = category        # Port Scan, DoS / Spike, Stealth Scan, etc.
        self.src_ip = src_ip
        self.target = target
        self.description = description
        self.mitre_ref = mitre_ref
        self.recommendation = recommendation


# ---------------------------------------------------------------------------
# Thread-Safe Rolling Packet Buffer & State
# ---------------------------------------------------------------------------
class PacketBuffer:
    """Thread-safe bounded memory storage for recent packets and security alerts."""
    def __init__(self, max_packets: int = 1500, max_alerts: int = 250):
        self.max_packets = max_packets
        self.max_alerts = max_alerts
        self.packets: deque = deque(maxlen=max_packets)
        self.alerts: deque = deque(maxlen=max_alerts)
        self.lock = threading.Lock()
        self.packet_counter: int = 0
        self.alert_counter: int = 0

    def add_packet(self, packet: PacketRecord):
        with self.lock:
            self.packet_counter += 1
            packet.index = self.packet_counter
            self.packets.append(packet)

    def add_alert(self, alert: SecurityAlert):
        with self.lock:
            self.alert_counter += 1
            alert.alert_id = self.alert_counter
            self.alerts.appendleft(alert)

    def get_packets(self) -> List[PacketRecord]:
        with self.lock:
            return list(self.packets)

    def get_alerts(self) -> List[SecurityAlert]:
        with self.lock:
            return list(self.alerts)

    def clear(self):
        with self.lock:
            self.packets.clear()
            self.alerts.clear()
            self.packet_counter = 0
            self.alert_counter = 0


# ---------------------------------------------------------------------------
# Stateful Anomaly Detection Engine
# ---------------------------------------------------------------------------
class SecurityAnomalyDetector:
    """
    Real-time stateful rule-based engine for intrusion and anomaly detection.
    Analyzes individual packets and sliding-window temporal patterns.
    """
    def __init__(
        self,
        port_scan_threshold: int = 12,
        port_scan_window: float = 25.0,
        flood_threshold: int = 40,
        flood_window: float = 4.0
    ):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.flood_threshold = flood_threshold
        self.flood_window = flood_window

        # Rolling state tracking per Source IP
        self.ip_port_tracker: Dict[str, List[Tuple[float, int, str]]] = {}
        self.ip_packet_tracker: Dict[str, List[float]] = {}
        self.icmp_tracker: Dict[str, List[float]] = {}

        # Cooldown dictionary to avoid flooding duplicate alerts: (src_ip, alert_type) -> last_alert_time
        self.alert_cooldowns: Dict[Tuple[str, str], float] = {}
        self.cooldown_period: float = 12.0  # seconds

    def clear_state(self):
        """Resets tracking caches and cooldown timers."""
        self.ip_port_tracker.clear()
        self.ip_packet_tracker.clear()
        self.icmp_tracker.clear()
        self.alert_cooldowns.clear()

    def _is_cooling_down(self, key: Tuple[str, str], current_time: float) -> bool:
        last_time = self.alert_cooldowns.get(key)
        if last_time is not None and abs(current_time - last_time) < self.cooldown_period:
            return True
        self.alert_cooldowns[key] = current_time
        return False

    def evaluate_packet(self, pkt: PacketRecord, buffer: PacketBuffer):
        """Inspects packet against stateless rules and sliding-window heuristics."""
        now = pkt.epoch
        src = pkt.src_ip
        dst = pkt.dst_ip
        dst_port = pkt.dst_port

        # Exclude loopback or broadcast from heavy external alerting if needed
        is_broadcast = src in ("0.0.0.0", "255.255.255.255")

        # -------------------------------------------------------------------
        # Rule 1: Port Scan Detection (Horizontal & Vertical Probe)
        # -------------------------------------------------------------------
        if dst_port is not None and not is_broadcast and src != "-":
            if src not in self.ip_port_tracker:
                self.ip_port_tracker[src] = []
            
            # Record probe: (time, dst_port, dst_ip)
            self.ip_port_tracker[src].append((now, dst_port, dst))

            # Evict entries older than window
            cutoff = now - self.port_scan_window
            self.ip_port_tracker[src] = [
                entry for entry in self.ip_port_tracker[src] if entry[0] >= cutoff
            ]

            unique_ports = {entry[1] for entry in self.ip_port_tracker[src]}
            if len(unique_ports) >= self.port_scan_threshold:
                if not self._is_cooling_down((src, "PORT_SCAN"), now):
                    pkt.is_suspicious = True
                    pkt.alert_tags.append("Port Scan")
                    scanned_sample = sorted(list(unique_ports))[:8]
                    ports_str = ", ".join(map(str, scanned_sample)) + ("..." if len(unique_ports) > 8 else "")
                    
                    alert = SecurityAlert(
                        alert_id=0,
                        timestamp=pkt.timestamp,
                        epoch=now,
                        severity="HIGH",
                        category="Port Scan Reconnaissance",
                        src_ip=src,
                        target=f"{dst} ({len(unique_ports)} ports)",
                        description=(
                            f"Host {src} probed {len(unique_ports)} distinct destination ports "
                            f"within {int(self.port_scan_window)}s (Sample ports: {ports_str})."
                        ),
                        mitre_ref="T1046 (Network Service Discovery)",
                        recommendation=(
                            "Investigate source endpoint for automated scanning tools (Nmap/Masscan). "
                            "Consider applying temporary rate-limiting or firewall block at network boundary."
                        )
                    )
                    buffer.add_alert(alert)

        # -------------------------------------------------------------------
        # Rule 2: High-Frequency Traffic Spike / DoS Flood
        # -------------------------------------------------------------------
        if not is_broadcast and src != "-":
            if src not in self.ip_packet_tracker:
                self.ip_packet_tracker[src] = []
            self.ip_packet_tracker[src].append(now)

            # Evict entries outside flood window
            cutoff_flood = now - self.flood_window
            self.ip_packet_tracker[src] = [
                t for t in self.ip_packet_tracker[src] if t >= cutoff_flood
            ]

            pkt_count = len(self.ip_packet_tracker[src])
            if pkt_count >= self.flood_threshold:
                if not self._is_cooling_down((src, "TRAFFIC_FLOOD"), now):
                    pkt.is_suspicious = True
                    pkt.alert_tags.append("Traffic Flood")
                    calculated_pps = round(pkt_count / self.flood_window, 1)

                    alert = SecurityAlert(
                        alert_id=0,
                        timestamp=pkt.timestamp,
                        epoch=now,
                        severity="CRITICAL",
                        category="High-Frequency Traffic Spike / DoS",
                        src_ip=src,
                        target=dst,
                        description=(
                            f"Abnormal burst from {src}: {pkt_count} packets in {self.flood_window}s "
                            f"(~{calculated_pps} pkts/s). Potential SYN Flood or Denial of Service activity."
                        ),
                        mitre_ref="T1498 (Network Denial of Service)",
                        recommendation=(
                            "Analyze flow characteristics. If volumetric attack is confirmed, engage upstream "
                            "anti-DDoS scrubbers, apply SYN cookies, or drop traffic from source IP."
                        )
                    )
                    buffer.add_alert(alert)

        # -------------------------------------------------------------------
        # Rule 3: Stealth TCP Scans (NULL, XMAS, SYN-FIN)
        # -------------------------------------------------------------------
        if pkt.protocol == "TCP":
            flags = pkt.flags.upper()
            is_stealth = False
            scan_type = ""

            if flags == "NULL" or flags == "-":
                is_stealth = True
                scan_type = "TCP NULL Scan (Flags = 0)"
            elif "FIN" in flags and "PSH" in flags and "URG" in flags:
                is_stealth = True
                scan_type = "TCP XMAS Scan (FIN+PSH+URG set)"
            elif "SYN" in flags and "FIN" in flags:
                is_stealth = True
                scan_type = "TCP SYN-FIN Scan (Invalid TCP State)"

            if is_stealth:
                pkt.is_suspicious = True
                pkt.alert_tags.append("Stealth Scan")
                if not self._is_cooling_down((src, scan_type), now):
                    alert = SecurityAlert(
                        alert_id=0,
                        timestamp=pkt.timestamp,
                        epoch=now,
                        severity="HIGH",
                        category="Stealth TCP Scan Signature",
                        src_ip=src,
                        target=f"{dst}:{dst_port}",
                        description=(
                            f"Detected anomalous TCP flag signature: {scan_type} from {src} to port {dst_port}. "
                            "Technique typically utilized for firewall rule evasion and OS fingerprinting."
                        ),
                        mitre_ref="T1046 (Network Service Discovery)",
                        recommendation=(
                            "Verify perimeter firewall stateful inspection. Stateful firewalls should drop "
                            "non-standard TCP flag combinations by default."
                        )
                    )
                    buffer.add_alert(alert)

        # -------------------------------------------------------------------
        # Rule 4: Cleartext / Insecure Protocol Usage
        # -------------------------------------------------------------------
        if dst_port in (21, 23, 445):
            insecure_map = {21: "FTP (Plaintext)", 23: "Telnet (Cleartext Credentials)", 445: "SMB (Direct Host)"}
            proto_name = insecure_map.get(dst_port, f"Port {dst_port}")
            pkt.is_suspicious = True
            pkt.alert_tags.append("Cleartext Protocol")

            if not self._is_cooling_down((src, f"CLEARTEXT_{dst_port}"), now):
                alert = SecurityAlert(
                    alert_id=0,
                    timestamp=pkt.timestamp,
                    epoch=now,
                    severity="MEDIUM",
                    category="Insecure Protocol Transmission",
                    src_ip=src,
                    target=f"{dst}:{dst_port} [{proto_name}]",
                    description=(
                        f"Detected connection to unencrypted service {proto_name} between {src} and {dst}. "
                        "Cleartext protocols expose authentication credentials and session payloads to packet sniffing."
                    ),
                    mitre_ref="T1040 (Network Sniffing) & T1552 (Unsecured Credentials)",
                    recommendation=(
                        "Migrate legacy services to encrypted protocols: replace Telnet with SSH (port 22) "
                        "and FTP with SFTP/FTPS. Block external ingress to port 445."
                    )
                )
                buffer.add_alert(alert)

        # -------------------------------------------------------------------
        # Rule 5: ICMP Echo Flood (Ping Flood)
        # -------------------------------------------------------------------
        if pkt.protocol == "ICMP" and "Echo Request" in pkt.info:
            if src not in self.icmp_tracker:
                self.icmp_tracker[src] = []
            self.icmp_tracker[src].append(now)

            # 3 second window
            cutoff_icmp = now - 3.0
            self.icmp_tracker[src] = [t for t in self.icmp_tracker[src] if t >= cutoff_icmp]

            if len(self.icmp_tracker[src]) >= 15:
                if not self._is_cooling_down((src, "ICMP_FLOOD"), now):
                    pkt.is_suspicious = True
                    pkt.alert_tags.append("ICMP Flood")
                    alert = SecurityAlert(
                        alert_id=0,
                        timestamp=pkt.timestamp,
                        epoch=now,
                        severity="MEDIUM",
                        category="ICMP Echo Flood / Ping Sweep",
                        src_ip=src,
                        target=dst,
                        description=(
                            f"Host {src} sent {len(self.icmp_tracker[src])} ICMP Echo Requests in 3.0s. "
                            "Indicates an aggressive ping sweep or ICMP flood attempt."
                        ),
                        mitre_ref="T1498.001 (Direct Network Flood)",
                        recommendation=(
                            "Implement ICMP rate-limiting on firewalls or routers to thwart ping sweeps."
                        )
                    )
                    buffer.add_alert(alert)


# ---------------------------------------------------------------------------
# Scapy Packet Parser Helper
# ---------------------------------------------------------------------------
def parse_scapy_packet(scapy_pkt: Any) -> Optional[PacketRecord]:
    """Extracts, formats, and enriches a Scapy packet into a PacketRecord."""
    try:
        now_epoch = float(scapy_pkt.time) if hasattr(scapy_pkt, "time") else time.time()
        dt = datetime.fromtimestamp(now_epoch)
        timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        src_ip = "-"
        dst_ip = "-"
        protocol = "Other"
        src_port = None
        dst_port = None
        service = "-"
        flags_str = ""
        info_str = ""
        length = len(scapy_pkt)

        # IP Layer parsing
        if scapy_pkt.haslayer(IP):
            src_ip = scapy_pkt[IP].src
            dst_ip = scapy_pkt[IP].dst
            proto_num = scapy_pkt[IP].proto
            protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, f"IP-{proto_num}")
        elif scapy_pkt.haslayer(IPv6):
            src_ip = scapy_pkt[IPv6].src
            dst_ip = scapy_pkt[IPv6].dst
            protocol = "IPv6"
        elif scapy_pkt.haslayer(ARP):
            src_ip = scapy_pkt[ARP].psrc
            dst_ip = scapy_pkt[ARP].pdst
            protocol = "ARP"
            op = "Who has" if scapy_pkt[ARP].op == 1 else "Is at"
            info_str = f"ARP {op} {dst_ip}? Tell {src_ip}"

        # Transport Layer parsing: TCP
        if scapy_pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = int(scapy_pkt[TCP].sport)
            dst_port = int(scapy_pkt[TCP].dport)
            
            # Resolve common service
            service = WELL_KNOWN_PORTS.get(dst_port) or WELL_KNOWN_PORTS.get(src_port) or f"Port-{dst_port}"

            # TCP Flags
            flags = scapy_pkt[TCP].flags
            flag_names = []
            if flags.F: flag_names.append("FIN")
            if flags.S: flag_names.append("SYN")
            if flags.R: flag_names.append("RST")
            if flags.P: flag_names.append("PSH")
            if flags.A: flag_names.append("ACK")
            if flags.U: flag_names.append("URG")
            flags_str = ",".join(flag_names) if flag_names else "NULL"
            info_str = f"{flags_str} -> Port {dst_port} [{service}]"

        # Transport Layer parsing: UDP
        elif scapy_pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = int(scapy_pkt[UDP].sport)
            dst_port = int(scapy_pkt[UDP].dport)
            service = WELL_KNOWN_PORTS.get(dst_port) or WELL_KNOWN_PORTS.get(src_port) or f"Port-{dst_port}"

            if scapy_pkt.haslayer(DNS):
                protocol = "DNS"
                dns = scapy_pkt[DNS]
                if dns.qr == 0 and dns.qd:
                    qname = dns.qd.qname.decode('utf-8', errors='ignore') if hasattr(dns.qd.qname, 'decode') else str(dns.qd.qname)
                    info_str = f"Standard Query: {qname.rstrip('.')}"
                elif dns.qr == 1:
                    info_str = f"DNS Response (Answers: {dns.ancount})"
                else:
                    info_str = f"DNS Packet -> Port {dst_port}"
            else:
                info_str = f"UDP -> Port {dst_port} [{service}]"

        # ICMP Layer
        elif scapy_pkt.haslayer(ICMP):
            protocol = "ICMP"
            icmp_type = scapy_pkt[ICMP].type
            icmp_code = scapy_pkt[ICMP].code
            if icmp_type == 8:
                info_str = "ICMP Echo Request (Ping)"
            elif icmp_type == 0:
                info_str = "ICMP Echo Reply (Pong)"
            elif icmp_type == 3:
                info_str = f"ICMP Destination Unreachable (Code {icmp_code})"
            else:
                info_str = f"ICMP Type {icmp_type} Code {icmp_code}"

        if not info_str:
            info_str = f"{protocol} Packet ({length} bytes)"

        # Hex / ASCII Dump preview
        hex_dump = ""
        try:
            raw_bytes = bytes(scapy_pkt)
            hex_lines = []
            for i in range(0, min(len(raw_bytes), 128), 16):
                chunk = raw_bytes[i:i+16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                hex_lines.append(f"{i:04x}   {hex_part:<48}  {ascii_part}")
            hex_dump = "\n".join(hex_lines)
            if len(raw_bytes) > 128:
                hex_dump += f"\n... [{len(raw_bytes) - 128} additional bytes truncated]"
        except Exception:
            hex_dump = "[Unable to extract hex dump]"

        return PacketRecord(
            index=0,
            timestamp=timestamp_str,
            epoch=now_epoch,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            service=service,
            length=length,
            flags=flags_str,
            info=info_str,
            hex_dump=hex_dump
        )
    except Exception as exc:
        # Fallback for malformed packet frames
        return None


# ---------------------------------------------------------------------------
# Background Sniffer Thread Manager
# ---------------------------------------------------------------------------
class SnifferThread(threading.Thread):
    """Background daemon thread executing Scapy sniffing without blocking Streamlit."""
    def __init__(
        self,
        buffer: PacketBuffer,
        detector: SecurityAnomalyDetector,
        interface: Optional[str] = None,
        bpf_filter: str = ""
    ):
        super().__init__(daemon=True)
        self.buffer = buffer
        self.detector = detector
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.stop_requested = threading.Event()
        self.error_message: Optional[str] = None

    def packet_callback(self, scapy_pkt):
        if self.stop_requested.is_set():
            return
        pkt_record = parse_scapy_packet(scapy_pkt)
        if pkt_record:
            self.detector.evaluate_packet(pkt_record, self.buffer)
            self.buffer.add_packet(pkt_record)

    def run(self):
        try:
            sniff_kwargs: Dict[str, Any] = {
                "prn": self.packet_callback,
                "store": False,
                "stop_filter": lambda x: self.stop_requested.is_set()
            }
            if self.interface and self.interface != "Default":
                sniff_kwargs["iface"] = self.interface
            if self.bpf_filter.strip():
                sniff_kwargs["filter"] = self.bpf_filter.strip()

            sniff(**sniff_kwargs)
        except Exception as exc:
            self.error_message = str(exc)

    def stop(self):
        self.stop_requested.set()


# ---------------------------------------------------------------------------
# Synthetic Attack & Traffic Generator (Zero-Permission Showcase Mode)
# ---------------------------------------------------------------------------
def generate_synthetic_traffic(buffer: PacketBuffer, detector: SecurityAnomalyDetector, scenario: str):
    """
    Simulates high-fidelity benign and attack traffic on demand.
    Enables instant demonstration in environments without root/Npcap privileges.
    """
    import random
    base_time = time.time()
    
    benign_domains = [
        "api.github.com", "login.microsoftonline.com", "cdn.cloudflare.net",
        "update.googleapis.com", "aws.amazon.com", "slack.com"
    ]
    internal_hosts = ["192.168.1.15", "192.168.1.22", "192.168.1.45", "192.168.1.60"]
    gateway_ip = "192.168.1.1"

    new_packets: List[PacketRecord] = []

    # 1. Normal Enterprise Traffic
    for i in range(15):
        t = base_time - (15 - i) * 0.4
        src = random.choice(internal_hosts)
        domain = random.choice(benign_domains)
        dst = f"142.250.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        # DNS Query
        dns_rec = PacketRecord(
            index=0,
            timestamp=datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            epoch=t,
            src_ip=src,
            dst_ip=gateway_ip,
            protocol="DNS",
            src_port=random.randint(49152, 65535),
            dst_port=53,
            service="DNS",
            length=78,
            flags="-",
            info=f"Standard Query: {domain}",
            hex_dump="0000   00 50 56 c0 00 08 00 0c 29 1a 2b 3c 08 00 45 00  .PV.....).+<..E."
        )
        new_packets.append(dns_rec)

        # HTTPS Handshake & TLS Application Data
        https_rec = PacketRecord(
            index=0,
            timestamp=datetime.fromtimestamp(t + 0.05).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            epoch=t + 0.05,
            src_ip=src,
            dst_ip=dst,
            protocol="TCP",
            src_port=random.randint(49152, 65535),
            dst_port=443,
            service="HTTPS",
            length=random.randint(120, 1420),
            flags="ACK,PSH",
            info="TLS Application Data -> Port 443 [HTTPS]",
            hex_dump="0000   17 03 03 01 20 00 00 00 00 00 00 00 01 a4 5f 9c  .... ........._."
        )
        new_packets.append(https_rec)

    # 2. Attack Simulation: Horizontal & Vertical Port Scan (Reconnaissance)
    if scenario in ("all", "port_scan"):
        attacker_ip = "192.168.1.105"
        victim_ip = "192.168.1.50"
        target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080]
        for idx, port in enumerate(target_ports):
            t = base_time + (idx * 0.1)
            scan_rec = PacketRecord(
                index=0,
                timestamp=datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                epoch=t,
                src_ip=attacker_ip,
                dst_ip=victim_ip,
                protocol="TCP",
                src_port=random.randint(50000, 60000),
                dst_port=port,
                service=WELL_KNOWN_PORTS.get(port, f"Port-{port}"),
                length=64,
                flags="SYN",
                info=f"SYN -> Port {port} [{WELL_KNOWN_PORTS.get(port, 'Unknown')}]",
                hex_dump=f"0000   45 00 00 3c 1a 2b 40 00 40 06 c8 10 c0 a8 01 69  E..<.+@.@......i"
            )
            new_packets.append(scan_rec)

    # 3. Attack Simulation: High-Frequency SYN Flood (Denial of Service)
    if scenario in ("all", "dos_flood"):
        dos_attacker = "10.0.0.88"
        target_server = "192.168.1.200"
        for idx in range(50):
            t = base_time + 1.8 + (idx * 0.04)
            flood_rec = PacketRecord(
                index=0,
                timestamp=datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                epoch=t,
                src_ip=dos_attacker,
                dst_ip=target_server,
                protocol="TCP",
                src_port=random.randint(1024, 65535),
                dst_port=80,
                service="HTTP",
                length=54,
                flags="SYN",
                info="SYN -> Port 80 [HTTP] (Flood probe)",
                hex_dump="0000   45 00 00 36 e1 a2 00 00 40 06 72 31 0a 00 00 58  E..6....@.r1...X"
            )
            new_packets.append(flood_rec)

    # 4. Attack Simulation: Stealth XMAS Scan (Firewall Evasion)
    if scenario in ("all", "stealth_scan"):
        stealth_ip = "192.168.1.220"
        t = base_time + 3.9
        xmas_rec = PacketRecord(
            index=0,
            timestamp=datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            epoch=t,
            src_ip=stealth_ip,
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=54321,
            dst_port=80,
            service="HTTP",
            length=60,
            flags="FIN,PSH,URG",
            info="FIN,PSH,URG -> Port 80 [HTTP] (Stealth XMAS Probe)",
            hex_dump="0000   45 00 00 3c 00 01 00 00 40 06 7c 3b c0 a8 01 dc  E..<....@.|;...."
        )
        new_packets.append(xmas_rec)

    # 5. Attack Simulation: Insecure Cleartext Telnet Session
    if scenario in ("all", "cleartext"):
        t = base_time + 4.1
        telnet_rec = PacketRecord(
            index=0,
            timestamp=datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            epoch=t,
            src_ip="172.16.4.15",
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=48210,
            dst_port=23,
            service="Telnet",
            length=92,
            flags="ACK,PSH",
            info="Telnet Auth Request: USER admin / PASS *******",
            hex_dump="0000   ff fd 18 ff fd 20 ff fd 23 ff fd 27 75 73 65 72  .... ..#..'user"
        )
        new_packets.append(telnet_rec)

    # Sort and feed to detector + buffer
    new_packets.sort(key=lambda p: p.epoch)
    for p in new_packets:
        detector.evaluate_packet(p, buffer)
        buffer.add_packet(p)


# ---------------------------------------------------------------------------
# Streamlit Session State Initialization
# ---------------------------------------------------------------------------
if "packet_buffer" not in st.session_state:
    st.session_state.packet_buffer = PacketBuffer(max_packets=2000, max_alerts=300)

if "anomaly_detector" not in st.session_state:
    st.session_state.anomaly_detector = SecurityAnomalyDetector(
        port_scan_threshold=12,
        port_scan_window=25.0,
        flood_threshold=40,
        flood_window=4.0
    )

if "sniffer_thread" not in st.session_state:
    st.session_state.sniffer_thread = None

if "is_sniffing" not in st.session_state:
    st.session_state.is_sniffing = False

if "last_refresh_time" not in st.session_state:
    st.session_state.last_refresh_time = time.time()

buffer: PacketBuffer = st.session_state.packet_buffer
detector: SecurityAnomalyDetector = st.session_state.anomaly_detector


# ---------------------------------------------------------------------------
# Sidebar: Controls & Capture Configuration
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ NetShield Console")
    st.caption("Network Threat Detection & Telemetry Platform")
    st.divider()

    # Capture Ingestion Mode Selector
    capture_mode = st.radio(
        "Ingestion Mode",
        ["🧪 Synthetic Simulation (Demo)", "📡 Live Interface Sniffing", "📁 Upload PCAP / PCAPNG"],
        index=0,
        help="Choose between simulated attack demo, real-time interface capture, or offline PCAP file parsing."
    )

    st.divider()

    # Mode 1: Live Interface Capture
    if capture_mode == "📡 Live Interface Sniffing":
        st.markdown("#### 📡 Live Capture Settings")
        
        available_ifaces = ["Default"]
        if SCAPY_AVAILABLE:
            try:
                available_ifaces += get_if_list()
            except Exception:
                pass

        selected_iface = st.selectbox("Select Network Interface", available_ifaces, index=0)
        bpf_filter = st.text_input(
            "BPF Capture Filter (Optional)",
            value="",
            placeholder="e.g. tcp, udp port 53, icmp",
            help="Standard Berkeley Packet Filter syntax applied directly at the packet driver level."
        )

        col_start, col_stop = st.columns(2)
        start_clicked = col_start.button("▶️ Start Sniffing", use_container_width=True, type="primary")
        stop_clicked = col_stop.button("⏹️ Stop Sniffing", use_container_width=True)

        if start_clicked:
            if not SCAPY_AVAILABLE:
                st.error("Scapy is not installed. Please check requirements.txt.")
            elif not st.session_state.is_sniffing:
                sniffer = SnifferThread(
                    buffer=buffer,
                    detector=detector,
                    interface=selected_iface if selected_iface != "Default" else None,
                    bpf_filter=bpf_filter
                )
                sniffer.start()
                st.session_state.sniffer_thread = sniffer
                st.session_state.is_sniffing = True
                st.success("Sniffer thread launched!")
                st.rerun()

        if stop_clicked:
            if st.session_state.is_sniffing and st.session_state.sniffer_thread:
                st.session_state.sniffer_thread.stop()
                st.session_state.is_sniffing = False
                st.info("Sniffer thread stopped.")
                st.rerun()

        if st.session_state.is_sniffing:
            st.markdown('<span class="status-pill status-running">● Live Sniffing Active</span>', unsafe_allow_html=True)
            # Check for thread-level capture errors (e.g. WinPcap missing)
            if st.session_state.sniffer_thread and st.session_state.sniffer_thread.error_message:
                st.error(f"Capture Exception: {st.session_state.sniffer_thread.error_message}")
                st.warning("Note: On Windows, live capture requires Npcap with WinPcap API compatibility and Administrator rights.")
                st.session_state.is_sniffing = False
        else:
            st.markdown('<span class="status-pill status-stopped">○ Sniffer Inactive</span>', unsafe_allow_html=True)

    # Mode 2: PCAP File Upload
    elif capture_mode == "📁 Upload PCAP / PCAPNG":
        st.markdown("#### 📁 Offline PCAP Forensics")
        uploaded_pcap = st.file_uploader("Upload Packet Capture (.pcap / .pcapng)", type=["pcap", "pcapng", "cap"])
        if uploaded_pcap is not None:
            if st.button("🚀 Parse & Ingest Capture File", type="primary", use_container_width=True):
                if not SCAPY_AVAILABLE:
                    st.error("Scapy library is required for PCAP parsing.")
                else:
                    with st.spinner("Decoding packets and analyzing security anomalies..."):
                        buffer.clear()
                        detector.clear_state()
                        import tempfile
                        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                            tmp.write(uploaded_pcap.read())
                            tmp_path = tmp.name
                        try:
                            scapy_packets = rdpcap(tmp_path)
                            count = 0
                            for spkt in scapy_packets:
                                rec = parse_scapy_packet(spkt)
                                if rec:
                                    detector.evaluate_packet(rec, buffer)
                                    buffer.add_packet(rec)
                                    count += 1
                            st.success(f"Successfully loaded and analyzed {count} packets!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed to parse PCAP: {e}")
                        finally:
                            if os.path.exists(tmp_path):
                                os.remove(tmp_path)

    # Mode 3: Synthetic / Demo Traffic Simulator
    else:
        st.markdown("#### 🧪 Traffic Simulator (Demo Mode)")
        st.caption("Generate realistic attack telemetry and normal web traffic instantly.")
        sim_scenario = st.selectbox(
            "Select Scenario",
            [
                ("all", "💥 Comprehensive Multi-Vector Attack & Web Traffic"),
                ("port_scan", "🔍 Rapid Nmap Port Scan (Reconnaissance)"),
                ("dos_flood", "⚡ High-Frequency SYN Flood (Denial of Service)"),
                ("stealth_scan", "🥷 Stealth XMAS TCP Scan (Firewall Evasion)"),
                ("cleartext", "🔓 Unencrypted Telnet Credentials Transmission")
            ],
            format_func=lambda x: x[1]
        )[0]

        if st.button("⚡ Inject Simulated Traffic", type="primary", use_container_width=True):
            generate_synthetic_traffic(buffer, detector, sim_scenario)
            st.success("Simulated packets injected and analyzed!")
            st.rerun()

    st.divider()

    # Anomaly Detection Sensitivity Sliders
    st.markdown("#### ⚙️ Threat Detection Tuning")
    port_scan_thresh = st.slider(
        "Port Scan Threshold (Probed Ports)",
        min_value=5, max_value=30, value=12, step=1,
        help="Trigger alert if single IP attempts connections to this many distinct ports within 25 seconds."
    )
    flood_thresh = st.slider(
        "DoS Flood Threshold (Burst Packets)",
        min_value=20, max_value=150, value=40, step=5,
        help="Trigger alert if single IP exceeds this packet count within a 4-second sliding window."
    )
    detector.port_scan_threshold = port_scan_thresh
    detector.flood_threshold = flood_thresh

    st.divider()

    # Maintenance & Buffer Actions
    st.markdown("#### 🧹 Session Actions")
    col_refresh, col_clear = st.columns(2)
    if col_refresh.button("🔄 Refresh", use_container_width=True):
        st.rerun()
    if col_clear.button("🗑️ Clear Logs", use_container_width=True):
        buffer.clear()
        detector.clear_state()
        st.toast("Traffic logs and security alerts cleared.", icon="🧹")
        st.rerun()


# ---------------------------------------------------------------------------
# Main Content Area: Header & SOC Metrics Overview
# ---------------------------------------------------------------------------
st.title("🛡️ NetShield | Network Packet Analyzer & Security Monitor")
st.markdown(
    "Real-time packet inspection, flow telemetry, and signature-based anomaly detection engine. "
    "Designed for SOC engineers, threat hunters, and network analysts."
)

# Fetch current snapshots
all_packets = buffer.get_packets()
all_alerts = buffer.get_alerts()

# Compute SOC metrics
total_packets_count = len(all_packets)
unique_src_ips = len(set(p.src_ip for p in all_packets if p.src_ip != "-"))
unique_dst_ips = len(set(p.dst_ip for p in all_packets if p.dst_ip != "-"))
total_alerts_count = len(all_alerts)

# Calculate Packets Per Second (PPS) throughput over last 5 seconds
now_ts = time.time()
recent_5s_packets = sum(1 for p in all_packets if now_ts - p.epoch <= 5.0)
current_pps = round(recent_5s_packets / 5.0, 1)

# Display Top KPI Metric Cards
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
kpi1.metric("Total Packets", f"{total_packets_count:,}", delta=f"{current_pps} pkts/s" if current_pps > 0 else None)
kpi2.metric("Unique Sources", f"{unique_src_ips:,}")
kpi3.metric("Unique Destinations", f"{unique_dst_ips:,}")
kpi4.metric(
    "Security Alerts",
    f"{total_alerts_count:,}",
    delta=f"{sum(1 for a in all_alerts if a.severity in ('CRITICAL', 'HIGH'))} High/Crit" if total_alerts_count > 0 else None,
    delta_color="inverse"
)
kpi5.metric("Buffer Capacity", f"{total_packets_count}/{buffer.max_packets}", delta="Rolling Window")

# High-Severity Alert Callout Drawer
critical_or_high_alerts = [a for a in all_alerts if a.severity in ("CRITICAL", "HIGH")]
if critical_or_high_alerts:
    latest_threat = critical_or_high_alerts[0]
    st.error(
        f"🚨 **ACTIVE {latest_threat.severity} ALERT:** {latest_threat.category} detected from **{latest_threat.src_ip}** "
        f"— {latest_threat.description} *(Ref: {latest_threat.mitre_ref})*"
    )

st.write("")

# ---------------------------------------------------------------------------
# Dashboard Tabs
# ---------------------------------------------------------------------------
tab_analytics, tab_table, tab_alerts, tab_docs = st.tabs([
    "📊 Traffic Visualizations",
    "📋 Live Traffic Log & Inspector",
    "🚨 Security Alerts & Threat Intel",
    "📖 Engine Architecture & Help"
])

# ---------------------------------------------------------------------------
# TAB 1: Traffic Visualizations
# ---------------------------------------------------------------------------
with tab_analytics:
    if not all_packets:
        st.info("💡 No packets captured yet. Use the sidebar to inject simulated traffic or start live capture.")
    else:
        df_viz = pd.DataFrame([p.to_dict() for p in all_packets])

        row1_col1, row1_col2 = st.columns(2)

        # 1. Top Communicating IP Addresses
        with row1_col1:
            st.markdown("##### 🌐 Top Communicating IP Addresses")
            src_counts = df_viz[df_viz["Source IP"] != "-"]["Source IP"].value_counts().head(8).reset_index()
            src_counts.columns = ["IP Address", "Packet Count"]

            if not src_counts.empty:
                fig_ips = px.bar(
                    src_counts,
                    x="Packet Count",
                    y="IP Address",
                    orientation="h",
                    color="Packet Count",
                    color_continuous_scale="Viridis",
                    text="Packet Count"
                )
                fig_ips.update_layout(
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=290,
                    yaxis=dict(autorange="reversed"),
                    coloraxis_showscale=False
                )
                st.plotly_chart(fig_ips, use_container_width=True)
            else:
                st.caption("No IP addresses available.")

        # 2. Protocol Breakdown (Donut Chart)
        with row1_col2:
            st.markdown("##### 🍰 Protocol Distribution")
            proto_counts = df_viz["Protocol"].value_counts().reset_index()
            proto_counts.columns = ["Protocol", "Count"]

            # Distinctive cyber security color mapping
            proto_colors = {
                "TCP": "#38bdf8",
                "UDP": "#818cf8",
                "ICMP": "#f43f5e",
                "DNS": "#34d399",
                "ARP": "#fbbf24",
                "Other": "#94a3b8"
            }
            colors = [proto_colors.get(p, "#94a3b8") for p in proto_counts["Protocol"]]

            fig_proto = go.Figure(data=[go.Pie(
                labels=proto_counts["Protocol"],
                values=proto_counts["Count"],
                hole=0.55,
                marker=dict(colors=colors),
                textinfo="label+percent",
                hoverinfo="label+value+percent"
            )])
            fig_proto.update_layout(
                margin=dict(l=10, r=10, t=10, b=10),
                height=290,
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_proto, use_container_width=True)

        row2_col1, row2_col2 = st.columns(2)

        # 3. Traffic Volume Over Time (Timeline)
        with row2_col1:
            st.markdown("##### 📈 Traffic Velocity Timeline")
            # Bucket packets into 2-second bins
            if len(all_packets) > 1:
                times = [datetime.fromtimestamp(p.epoch) for p in all_packets]
                df_time = pd.DataFrame({"time": times})
                df_time["second"] = df_time["time"].dt.floor("1s")
                rate_df = df_time.groupby("second").size().reset_index(name="Packets")

                fig_time = px.area(
                    rate_df,
                    x="second",
                    y="Packets",
                    color_discrete_sequence=["#38bdf8"]
                )
                fig_time.update_layout(
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=290,
                    xaxis_title="",
                    yaxis_title="Packets / Sec"
                )
                st.plotly_chart(fig_time, use_container_width=True)
            else:
                st.caption("Collecting data points for timeline...")

        # 4. Top Targeted Destination Ports & Services
        with row2_col2:
            st.markdown("##### 🎯 Targeted Destination Ports & Services")
            port_records = [
                f"{p.dst_port} ({p.service})"
                for p in all_packets
                if p.dst_port is not None and p.dst_port != "-"
            ]
            if port_records:
                port_counts = Counter(port_records).most_common(8)
                df_ports = pd.DataFrame(port_counts, columns=["Port & Service", "Packets"])

                fig_ports = px.bar(
                    df_ports,
                    x="Port & Service",
                    y="Packets",
                    color="Packets",
                    color_continuous_scale="Plasma",
                    text="Packets"
                )
                fig_ports.update_layout(
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=290,
                    xaxis_tickangle=-30,
                    coloraxis_showscale=False
                )
                st.plotly_chart(fig_ports, use_container_width=True)
            else:
                st.caption("No port information captured.")


# ---------------------------------------------------------------------------
# TAB 2: Live Traffic Log & Packet Inspector
# ---------------------------------------------------------------------------
with tab_table:
    if not all_packets:
        st.info("💡 No packets captured yet. Generate traffic or start sniffing via the sidebar.")
    else:
        # Filter controls
        f_col1, f_col2, f_col3, f_col4 = st.columns([2, 2, 2, 2])
        
        all_protocols = sorted(list(set(p.protocol for p in all_packets)))
        selected_proto = f_col1.multiselect("Filter Protocol", all_protocols, default=[])
        search_ip = f_col2.text_input("Search IP Address", placeholder="e.g. 192.168.1.105")
        suspicious_only = f_col3.checkbox("⚠️ Show Only Suspicious Packets", value=False)
        
        # Build filtered list
        filtered = all_packets
        if selected_proto:
            filtered = [p for p in filtered if p.protocol in selected_proto]
        if search_ip.strip():
            query = search_ip.strip()
            filtered = [p for p in filtered if query in p.src_ip or query in p.dst_ip]
        if suspicious_only:
            filtered = [p for p in filtered if p.is_suspicious]

        st.caption(f"Showing **{len(filtered)}** of **{len(all_packets)}** captured packets")

        # Convert to displayable DataFrame (reverse chronological)
        table_data = [p.to_dict() for p in reversed(filtered)]
        df_table = pd.DataFrame(table_data)

        if not df_table.empty:
            st.dataframe(
                df_table,
                use_container_width=True,
                height=380,
                hide_index=True
            )

            # CSV Download Button
            csv_bytes = df_table.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Export Filtered Packets as CSV",
                data=csv_bytes,
                file_name=f"netshield_capture_{int(time.time())}.csv",
                mime="text/csv",
                use_container_width=False
            )
        else:
            st.warning("No packets match the current filter criteria.")

        st.divider()

        # Deep Packet Hex/ASCII Inspector
        st.markdown("##### 🔬 Deep Packet Inspector")
        if filtered:
            inspect_indices = [p.index for p in reversed(filtered)][:100]
            selected_id = st.selectbox("Select Packet ID to Inspect", inspect_indices)
            
            target_pkt = next((p for p in all_packets if p.index == selected_id), None)
            if target_pkt:
                insp_col1, insp_col2 = st.columns([1, 2])
                with insp_col1:
                    st.markdown("**Packet Metadata**")
                    st.markdown(f"- **Packet ID:** `#{target_pkt.index}`")
                    st.markdown(f"- **Timestamp:** `{target_pkt.timestamp}`")
                    st.markdown(f"- **Flow:** `{target_pkt.src_ip}:{target_pkt.src_port or '-'}` ➡️ `{target_pkt.dst_ip}:{target_pkt.dst_port or '-'}`")
                    st.markdown(f"- **Protocol:** `{target_pkt.protocol}` ({target_pkt.service})")
                    st.markdown(f"- **Length:** `{target_pkt.length} bytes`")
                    st.markdown(f"- **TCP Flags:** `{target_pkt.flags or '-'}`")
                    st.markdown(f"- **Security Status:** `{'⚠️ Suspicious' if target_pkt.is_suspicious else 'Normal'}`")
                    if target_pkt.alert_tags:
                        st.markdown(f"- **Triggered Rules:** `{', '.join(target_pkt.alert_tags)}`")

                with insp_col2:
                    st.markdown("**Hex & ASCII Layer Payload**")
                    st.code(target_pkt.hex_dump if target_pkt.hex_dump else "No payload dump available.", language="text")


# ---------------------------------------------------------------------------
# TAB 3: Security Alerts & Threat Intel
# ---------------------------------------------------------------------------
with tab_alerts:
    st.markdown("### 🚨 Threat Intelligence & Anomaly Events")
    
    if not all_alerts:
        st.success("✅ **All Clear:** No malicious patterns, port scans, or volumetric spikes detected in current buffer.")
    else:
        # Severity breakdown metrics
        sev_counts = Counter(a.severity for a in all_alerts)
        sc1, sc2, sc3, sc4 = st.columns(4)
        sc1.markdown(f"**🔴 Critical:** `{sev_counts.get('CRITICAL', 0)}`")
        sc2.markdown(f"**🟠 High:** `{sev_counts.get('HIGH', 0)}`")
        sc3.markdown(f"**🟡 Medium:** `{sev_counts.get('MEDIUM', 0)}`")
        sc4.markdown(f"**🔵 Total Alerts:** `{len(all_alerts)}`")
        st.divider()

        # Render alert cards
        for alert in all_alerts:
            card_class = {
                "CRITICAL": "alert-card-critical",
                "HIGH": "alert-card-high",
                "MEDIUM": "alert-card-medium"
            }.get(alert.severity, "alert-card-medium")

            badge_class = f"badge-{alert.severity.lower()}"

            st.markdown(f"""
            <div class="{card_class}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div>
                        <span class="alert-badge {badge_class}">{alert.severity}</span>
                        <strong style="font-size: 1.05rem; color: #f8fafc;">{alert.category}</strong>
                    </div>
                    <span style="font-size: 0.8rem; color: #94a3b8;">🕒 {alert.timestamp}</span>
                </div>
                <div style="margin-top: 6px; font-size: 0.92rem; color: #e2e8f0;">
                    {alert.description}
                </div>
                <div style="margin-top: 8px; font-size: 0.85rem; color: #94a3b8;">
                    <strong>Source Host:</strong> <code style="color: #fca5a5;">{alert.src_ip}</code> &nbsp;|&nbsp;
                    <strong>Target:</strong> <code>{alert.target}</code> &nbsp;|&nbsp;
                    <strong>Framework Mapping:</strong> <span style="color: #38bdf8;">{alert.mitre_ref}</span>
                </div>
                <div style="margin-top: 8px; padding-top: 6px; border-top: 1px dashed rgba(255,255,255,0.15); font-size: 0.84rem; color: #cbd5e1;">
                    <strong>🛡️ Recommended Action:</strong> {alert.recommendation}
                </div>
            </div>
            """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# TAB 4: Engine Architecture & Help
# ---------------------------------------------------------------------------
with tab_docs:
    st.markdown("""
    ### 🛡️ System Architecture & Detection Specifications

    #### 1. Real-Time Packet Sniffing & Ingestion
    - **Scapy Engine:** Packets are processed asynchronously via a daemon thread running Scapy's `sniff()` function with non-blocking callbacks.
    - **Memory Guard:** Packets are committed to a thread-safe `collections.deque(maxlen=2000)` protected by a mutex lock, preventing memory bloat during high-throughput capture sessions.
    - **Windows / Npcap Compatibility:** On Windows platforms, raw socket capture requires [Npcap](https://npcap.com/) installed with WinPcap API-compatible mode enabled. If elevated permissions are unavailable, users can seamlessly use the built-in **Traffic Simulator** or upload **PCAP** files.

    #### 2. Anomaly Detection Heuristics & Rules
    | Rule Engine | Logic & Mathematical Condition | Security Objective |
    | :--- | :--- | :--- |
    | **Port Scan Detector** | $\text{Distinct Destination Ports} \ge 12$ from a single source within $25\text{s}$ | Catches reconnaissance tools (Nmap, Masscan, Angry IP). |
    | **DoS / Flood Detector** | $\text{Packet Volume} \ge 40$ packets within a $4\text{s}$ window ($\ge 10\text{ pps}$) | Catches high-volume SYN floods, UDP floods, and volumetric DoS. |
    | **Stealth Scan Signatures** | Inspects TCP control flags for NULL (`0`), XMAS (`FIN+PSH+URG`), and SYN-FIN | Flags evasion attempts designed to bypass legacy stateless firewalls. |
    | **Cleartext Protocol Check** | Identifies ingress/egress to ports 21 (FTP), 23 (Telnet), or 445 (SMB) | Prevents cleartext credential exposure and unencrypted management sessions. |
    | **ICMP Ping Flood** | Evaluates ICMP Type 8 (Echo Request) volume exceeding $15$ pings in $3\text{s}$ | Detects ping sweeps and smurf/ping-of-death attacks. |

    #### 3. Enterprise Integration
    - All alerts map directly to **MITRE ATT&CK** Enterprise tactics (Reconnaissance, Initial Access, Denial of Service).
    - Traffic logs support one-click CSV export for ingestion into enterprise SIEMs (Splunk, Elastic, Sentinel).
    """)

# ---------------------------------------------------------------------------
# Auto-Refresh Mechanism for Live Sniffing
# ---------------------------------------------------------------------------
if st.session_state.is_sniffing:
    time.sleep(2)
    st.rerun()
