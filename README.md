# SOC Network Traffic Analysis & Threat Intelligence Enrichment Pipeline

## SOC Analyst / Cybersecurity Engineer / Threat Hunter Project

---

## 🧭 Project Summary

This project implements a lightweight SOC-style network security pipeline that analyzes packet capture (PCAP) files, extracts network indicators, and enriches them with threat intelligence to detect suspicious or malicious communication patterns.

It simulates real-world SOC workflows including network traffic analysis, IOC enrichment, asset baselining, and alert triage to identify potential command-and-control (C2) activity and unknown external communications.

---

## 🛠️ Features

### 🔍 PCAP Network Traffic Analysis
- Parses Wireshark-generated `.pcap` files using Python
- Extracts key indicators:
  - DNS query logs
  - HTTP host headers
  - TLS SNI (encrypted traffic metadata)
- Supports analysis of both encrypted and unencrypted traffic

---

### 📊 Known Host Baseline System
- Maintains a lightweight allowlist of trusted domains (CSV-based)
- Includes:
  - Cloud providers
  - SaaS platforms
  - Internal infrastructure
- Reduces false positives by filtering known-safe traffic

---

### 🌐 Threat Intelligence Enrichment
- Integrates **VirusTotal API** for external reputation analysis
- Enriches unknown hosts with:
  - Malicious / suspicious / harmless scores
  - Vendor detection results
  - Community threat intelligence

---

### ⚖️ Host Classification Engine
Each host is classified into:

- `KNOWN_GOOD`
- `LIKELY_SAFE_BUT_UNKNOWN`
- `SUSPICIOUS`
- `MALICIOUS`

This enables rapid triage of network-based security events.

---

## 🧠 Security Capabilities Demonstrated

- Network Traffic Analysis (NTA)
- PCAP forensic investigation
- Command-and-Control (C2) detection concepts
- Threat intelligence correlation (IOC enrichment)
- Asset baseline vs anomaly detection
- Security event classification and triage logic
- Behavioral analysis of network communications

---

## 🏗️ Architecture

```text
PCAP Capture (Wireshark / TShark)
          ↓
Python PCAP Parser (pyshark)
          ↓
Protocol Extraction (DNS / HTTP / TLS SNI)
          ↓
Known Host Baseline Lookup (CSV)
          ↓
VirusTotal API Enrichment
          ↓
Risk Classification Engine
          ↓
Security Output Report


## 📸 Sample Output


google.com → KNOWN_GOOD
github.com → KNOWN_GOOD
malicious-site.xyz → MALICIOUS
unknown-host.net → UNKNOWN


## 🖥️ Terminal View
Example execution of the SOC PCAP Analysis tool showing host extraction, VirusTotal enrichment, and risk classification.

![SOC Analysis Output](screenshots/sample_output.PNG)

---