# 🛡️ PRODIGY_CS_05 — Network Packet Analyzer

This is Task 5 of the Cybersecurity track from Prodigy Infotech.

A lightweight Python-based network packet analyzer developed using Scapy.
This tool captures and inspects live network traffic, displaying source and destination IPs, protocol types (TCP/UDP), and promoting responsible cybersecurity practices.

---

## 📌 Project Overview

- 🔍 Capture real-time network packets
- 📡 Identify source & destination IP addresses
- 🔁 Detect protocol types: TCP / UDP
- ⚙️ Run securely in a Python virtual environment
- 🐧 Designed and tested on Kali Linux

---

## 🧰 Prerequisites

- ✅ Python 3.10+ (PEP 668 compliant)
- 🐍 Virtual environment tools (venv)
- 📦 Pip (Python package installer)
- 🧪 Scapy (packet analysis library)
- 🐧 Kali Linux or other Linux distro with root access

---

## ⚙️ Setup Instructions (Kali Linux)

Clone the repository:

```bash
git clone https://github.com/Jetlin_Figarez/PRODIGY_CS_05-Network-Packet-Analyzer.git
cd PRODIGY_CS_05-Network-Packet-Analyzer

# Create and activate the virtual environment:

 python3 -m venv .venv
 source .venv/bin/activate

# Upgrade pip and install dependencies:

 python -m pip install --upgrade pip
 pip install -r requirements.txt

# Verify installation (optional):

 python --version
 pip list

📝 Note: This setup is compatible with systems enforcing PEP 668 (externally managed environments).
Avoid installing packages globally.

# 🚀 Running the Sniffer

 Start the analyzer (requires sudo for packet capture):

 sudo python3 sniffer.py

# Sample output:
 
  [*] Starting Packet Sniffer... Press Ctrl+C to stop.
  [TCP] 192.168.1.5 -> 172.217.11.14
  [UDP] 192.168.1.5 -> 8.8.8.8

  To stop: Press Ctrl + C

# 📁 Project Structure

File	Description
sniffer.py	Main packet analyzer script
requirements.txt	Python dependencies
README.md

# 🔐 Ethical Use Notice

This tool is intended for:

    Educational and research purposes

    Use in authorized environments only

    Hands-on cybersecurity learning

# ❌ Do NOT use this tool on public or unauthorized networks.
