# Security Policy

## 🔐 Project Scope

This project is a SOC-style network traffic analysis tool designed for:
- PCAP forensic analysis
- Threat intelligence enrichment (VirusTotal API)
- Network-based threat detection (DNS, HTTP, TLS SNI)

It is intended for:
- Educational purposes
- Cybersecurity training
- SOC simulation and threat hunting practice

It is NOT intended for production defensive deployment.

---

## 📌 Supported Versions

As this is a continuously evolving security research project, only the latest version in the main branch is supported.

| Branch | Status |
|--------|--------|
| main   | ✅ Active development |
| older commits | ❌ Unsupported |

---

## 🚨 Reporting a Vulnerability

If you discover a security issue or potential misuse scenario:

Please report it via GitHub Issues:
https://github.com/unicornautomata/PCAP_HOST_VALIDATOR/issues

### What to include:
- Description of the issue
- Steps to reproduce
- Sample PCAP or host (if applicable)
- Expected vs actual behavior

---

## ⏱ Response Time

- Acknowledgement: within 48–72 hours
- Initial review: within 5–7 days (best effort)

---

## ⚠️ Security Considerations

- VirusTotal API key must never be exposed in code
- PCAP files may contain sensitive network metadata
- Use only in authorized environments

---

## 🧠 Responsible Disclosure

Please do not publicly disclose vulnerabilities before they are addressed.