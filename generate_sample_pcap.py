"""
=============================================================================
Sample PCAP Generator for NetShield Network Packet Analyzer
=============================================================================
Generates a realistic sample packet capture (sample_traffic.pcap) containing:
1. Normal enterprise traffic (DNS queries, HTTPS TLS web traffic, NTP)
2. Nmap horizontal/vertical Port Scan
3. High-frequency SYN flood (DoS probe)
4. Stealth TCP XMAS scan (FIN+PSH+URG flags)
5. Cleartext Telnet authentication session
=============================================================================
"""

import os
import time
import random
from datetime import datetime

try:
    from scapy.all import (
        wrpcap, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw
    )
except ImportError:
    print("[!] Scapy is required to generate the sample PCAP. Install with: pip install scapy")
    exit(1)


def generate_pcap(output_filename: str = "sample_traffic.pcap"):
    print(f"[*] Generating synthetic network traffic trace: {output_filename} ...")
    packets = []
    base_time = time.time() - 60  # Start 1 minute ago

    gateway_mac = "00:50:56:c0:00:08"
    client_mac = "00:0c:29:1a:2b:3c"
    attacker_mac = "00:0c:29:ff:ee:dd"

    client_ip = "192.168.1.45"
    gateway_ip = "192.168.1.1"
    victim_server = "192.168.1.50"
    dns_server = "8.8.8.8"

    # 1. Normal Web & DNS Traffic
    domains = ["api.github.com", "login.microsoftonline.com", "aws.amazon.com", "cloudflare.com"]
    for i, domain in enumerate(domains):
        t = base_time + (i * 2.5)
        # DNS Query
        dns_req = Ether(src=client_mac, dst=gateway_mac) / \
                  IP(src=client_ip, dst=dns_server) / \
                  UDP(sport=random.randint(50000, 60000), dport=53) / \
                  DNS(rd=1, qd=DNSQR(qname=domain))
        dns_req.time = t
        packets.append(dns_req)

        # DNS Response
        resolved_ip = f"104.244.{random.randint(40, 50)}.{random.randint(1, 200)}"
        dns_resp = Ether(src=gateway_mac, dst=client_mac) / \
                   IP(src=dns_server, dst=client_ip) / \
                   UDP(sport=53, dport=dns_req[UDP].sport) / \
                   DNS(qr=1, aa=1, qd=DNSQR(qname=domain),
                       an=DNSRR(rrname=domain, ttl=300, rdata=resolved_ip))
        dns_resp.time = t + 0.04
        packets.append(dns_resp)

        # HTTPS 3-Way Handshake
        c_port = random.randint(50000, 60000)
        syn = Ether(src=client_mac, dst=gateway_mac) / \
              IP(src=client_ip, dst=resolved_ip) / \
              TCP(sport=c_port, dport=443, flags="S", seq=1000)
        syn.time = t + 0.08
        packets.append(syn)

        syn_ack = Ether(src=gateway_mac, dst=client_mac) / \
                  IP(src=resolved_ip, dst=client_ip) / \
                  TCP(sport=443, dport=c_port, flags="SA", seq=2000, ack=1001)
        syn_ack.time = t + 0.12
        packets.append(syn_ack)

        ack = Ether(src=client_mac, dst=gateway_mac) / \
              IP(src=client_ip, dst=resolved_ip) / \
              TCP(sport=c_port, dport=443, flags="A", seq=1001, ack=2001)
        ack.time = t + 0.14
        packets.append(ack)

        # TLS Data
        tls_data = Ether(src=client_mac, dst=gateway_mac) / \
                   IP(src=client_ip, dst=resolved_ip) / \
                   TCP(sport=c_port, dport=443, flags="PA", seq=1001, ack=2001) / \
                   Raw(load=b"\x17\x03\x03\x00\x40" + b"\xaa" * 64)
        tls_data.time = t + 0.20
        packets.append(tls_data)

    # 2. Port Scan Attack Simulation (Reconnaissance)
    attacker_ip = "192.168.1.105"
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080]
    scan_start = base_time + 15.0
    for idx, port in enumerate(scan_ports):
        probe = Ether(src=attacker_mac, dst=gateway_mac) / \
                IP(src=attacker_ip, dst=victim_server) / \
                TCP(sport=random.randint(45000, 65000), dport=port, flags="S", seq=5000 + idx)
        probe.time = scan_start + (idx * 0.12)
        packets.append(probe)

    # 3. High-Frequency SYN Flood (Denial of Service)
    dos_ip = "10.0.0.88"
    dos_start = base_time + 25.0
    for i in range(55):
        syn_flood = Ether(src=attacker_mac, dst=gateway_mac) / \
                    IP(src=dos_ip, dst=victim_server) / \
                    TCP(sport=random.randint(1024, 65535), dport=80, flags="S", seq=i * 100)
        syn_flood.time = dos_start + (i * 0.05)
        packets.append(syn_flood)

    # 4. Stealth TCP XMAS Scan (Firewall Evasion)
    stealth_ip = "192.168.1.220"
    xmas = Ether(src=attacker_mac, dst=gateway_mac) / \
           IP(src=stealth_ip, dst=victim_server) / \
           TCP(sport=59999, dport=80, flags="FPU", seq=8888)
    xmas.time = base_time + 35.0
    packets.append(xmas)

    # 5. Cleartext Telnet Session
    telnet_ip = "172.16.4.15"
    telnet_start = base_time + 40.0
    telnet_pkt = Ether(src=client_mac, dst=gateway_mac) / \
                 IP(src=telnet_ip, dst=gateway_ip) / \
                 TCP(sport=43210, dport=23, flags="PA", seq=9999) / \
                 Raw(load=b"USER admin\r\nPASS Winter2026!\r\n")
    telnet_pkt.time = telnet_start
    packets.append(telnet_pkt)

    # Sort packets strictly by timestamp
    packets.sort(key=lambda p: float(p.time))

    # Write PCAP
    wrpcap(output_filename, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {output_filename}")


if __name__ == "__main__":
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_file = os.path.join(out_dir, "sample_traffic.pcap")
    generate_pcap(out_file)
