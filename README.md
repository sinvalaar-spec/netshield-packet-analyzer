# 🛡️ NetShield: Network Packet Analyzer & Security Monitoring Dashboard

A lightweight, portfolio-ready **Network Packet Analyzer & Security Monitoring Dashboard** built with **Python**, **Scapy**, and **Streamlit**. 

NetShield captures, parses, and visualizes live or recorded network traffic in real time. It features a built-in **Rule-Based Anomaly Detection Engine** designed to detect common cyber reconnaissance and DoS attack patterns—including port scans, TCP SYN floods, stealth TCP flag scans, and unencrypted cleartext protocols—presenting them in an interactive, SOC-style interface.

---

## 🌟 Key Features

* **Multi-Mode Packet Ingestion:**
  * 📡 **Live Interface Sniffing:** Non-blocking real-time capture from local network adapters using Scapy.
  * 📁 **PCAP / PCAPNG Ingestion:** Offline analysis for incident response and packet forensics.
  * 🧪 **Zero-Privilege Simulation (Demo Mode):** Built-in synthetic traffic generator simulating realistic web traffic and live cyber attacks without needing Administrator/Npcap permissions.
* **SOC Overview Metrics:**
  * Total packets captured and real-time Packet-per-Second (PPS) throughput.
  * Unique source and destination IP counts.
  * Active security alert counter with severity categorization.
* **Interactive Threat & Traffic Visualizations (Plotly):**
  * **Top Communicating IP Addresses:** Identifies top talkers and prospective scanners.
  * **Protocol Distribution:** Donut chart breaking down TCP, UDP, ICMP, DNS, and ARP traffic.
  * **Traffic Volume Timeline:** Rolling time-series tracking packet velocity and sudden bursts.
  * **Targeted Ports & Services:** Distribution of standard services (HTTPS, HTTP, SSH, DNS, SMB, etc.).
* **Searchable Traffic Log Table & Packet Inspector:**
  * Filter by protocol, IP address search, or isolate suspicious packets with a single toggle.
  * Deep-packet inspection modal displaying raw hex/ASCII payloads and layer headers.
  * One-click CSV export for offline forensic reporting.
* **Thread-Safe Rolling Queue Architecture:**
  * Bounded memory footprint using `collections.deque` with thread locking to ensure the dashboard remains lightning-fast without memory leaks.

---

## 🧠 How the Anomaly Detection Engine Works

The dashboard continuously evaluates incoming packets over sliding time windows against cybersecurity threat signatures:

```
                                 [ Incoming Packet Stream ]
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
            [ Stateful Window Analysis ]               [ Stateless Packet Inspection ]
                       │                                           │
         ┌─────────────┴─────────────┐               ┌─────────────┴─────────────┐
         ▼                           ▼               ▼                           ▼
  [ Port Scan Engine ]       [ Flood / DoS Engine ] [ Stealth Flags ]   [ Cleartext Protocols ]
  Unique ports probed        High packet burst rate  NULL (flags=0)      Telnet (23), FTP (21)
  ≥ threshold in 30s         ≥ threshold in 5s       XMAS (F+P+U)        Plaintext credentials
         │                           │               │                           │
         └─────────────┬─────────────┴───────────────┴───────────────────────────┘
                       ▼
            [ Security Alert Triggered ]
         (Severity: Critical / High / Medium)
```

| Detection Rule | Threat Vector | Technical Logic | MITRE ATT&CK Reference |
| :--- | :--- | :--- | :--- |
| **Port Scan Detection** | Reconnaissance / Network Discovery | Flags any single Source IP that attempts connections to $\ge 15$ distinct Destination Ports within a rolling 30-second window. | **T1046:** Network Service Discovery |
| **Traffic Spike / Flood** | Denial of Service (DoS / DDoS) | Detects anomalous packet volume surges exceeding 40 packets/sec or $> 60$ packets from a single Source IP in a 5-second interval. | **T1498:** Network Denial of Service |
| **Stealth TCP Scans** | Firewall Evasion / Probing | Identifies abnormal TCP flag combinations that violate standard state machines: **NULL Scans** (flags=0), **XMAS Scans** (FIN+PSH+URG), and **SYN-FIN** scans. | **T1046:** Network Service Discovery |
| **Cleartext Protocol Risk** | Credential Sniffing / Insecure Services | Alerts on unencrypted legacy traffic targeting Telnet (Port 23), unencrypted FTP (Port 21), or SMB (Port 445). | **T1040:** Network Sniffing |
| **ICMP Echo Flood** | Ping Sweep / ICMP Flood | Flags rapid bursts of ICMP Echo Requests (Ping) exceeding 20 pings/sec from a single source. | **T1498.001:** Direct Network Flood |

---

## 🚀 Quick Start Guide

### 1. Prerequisites
* **Python 3.10+**
* On **Windows**:
  * For live capture, install [Npcap](https://npcap.com/) with *"Install Npcap in WinPcap API-compatible Mode"* enabled, and run your command prompt as Administrator.
  * *Note: If Npcap or Administrator privileges are not available, simply use the built-in **Synthetic Traffic Simulator** or upload a **PCAP** file!*
* On **Linux / macOS**:
  * Live capture typically requires root permissions (`sudo`).

### 2. Installation

Clone this repository and create a virtual environment:

```bash
# Clone the repository
git clone https://github.com/your-username/network-packet-analyzer.git
cd network-packet-analyzer

# Create and activate virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Launching the Dashboard

Run the Streamlit application:

```bash
streamlit run app.py
```

Open your browser at `http://localhost:8501`.

---

## 💻 Operating Modes

1. **🧪 Simulation / Demo Mode (Recommended for testing & portfolio evaluation):**
   * Select **"🧪 Synthetic Traffic Simulation"** in the sidebar.
   * Click **"Generate Simulated Attack & Traffic"** or enable **"Continuous Background Generator"**.
   * Instantly observes port scans, SYN floods, cleartext Telnet sessions, and benign HTTPS/DNS traffic populate charts and trigger alerts.
2. **📡 Live Network Sniffing:**
   * Select **"📡 Live Network Capture"** in the sidebar.
   * Choose your network interface (e.g., Ethernet or Wi-Fi).
   * Optionally specify a BPF filter (e.g., `tcp`, `udp port 53`, `icmp`).
   * Click **"▶️ Start Sniffing"**.
3. **📁 PCAP File Analysis:**
   * Select **"📁 Upload PCAP / PCAPNG"**.
   * Drag and drop any `.pcap` or `.pcapng` capture file to ingest and inspect immediately.

---

## 📁 Repository Structure

```
├── app.py                  # Main Streamlit dashboard, packet capture engine, and anomaly detection rules
├── requirements.txt        # Python package dependencies (streamlit, scapy, pandas, plotly)
├── README.md               # Documentation and architecture guide
└── sample_traffic.pcap     # Optional bundled sample capture file
```

---

## 🔒 Security & Ethical Disclaimer

This tool is created strictly for **authorized network monitoring, defensive security engineering, educational research, and portfolio demonstration**. Always ensure you have explicit written authorization before monitoring or capturing traffic on any network.
