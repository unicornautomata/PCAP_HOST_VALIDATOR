import pyshark
import requests
import pandas as pd
import os

# ======================
# CONFIG
# ======================
VT_API_KEY = os.getenv("VT_API_KEY")  # safer than hardcoding
PCAP_FILE = "capture.pcap"

KNOWN_HOSTS_FILE = "known_hosts.csv"

BASE_URL = "https://www.virustotal.com/api/v3"

headers = {
    "x-apikey": VT_API_KEY
}

# ======================
# LOAD KNOWN HOSTS DB
# ======================
def load_known_hosts():
    try:
        df = pd.read_csv(KNOWN_HOSTS_FILE)
        return set(df["host"].str.lower())
    except Exception:
        return set()

known_hosts = load_known_hosts()

# ======================
# VIRUSTOTAL CHECK
# ======================
def vt_check_host(host):
    url = f"{BASE_URL}/domains/{host}"

    try:
        r = requests.get(url, headers=headers)
        data = r.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }

    except Exception:
        return None

# ======================
# EXTRACT HOSTS FROM PCAP
# ======================
def extract_hosts(pcap_file):
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)

    hosts = set()

    for packet in capture:
        try:
            # DNS queries
            if hasattr(packet, "dns") and hasattr(packet.dns, "qry_name"):
                hosts.add(packet.dns.qry_name.lower())

            # HTTP Host header
            if hasattr(packet, "http") and hasattr(packet.http, "host"):
                hosts.add(packet.http.host.lower())

            # TLS SNI (very important for C2 detection)
            if hasattr(packet, "tls") and hasattr(packet.tls, "handshake_extensions_server_name"):
                hosts.add(packet.tls.handshake_extensions_server_name.lower())

        except Exception:
            continue

    return hosts

# ======================
# CLASSIFY HOST
# ======================
def classify_host(host):
    # 1. Known good list
    if host in known_hosts:
        return "KNOWN_GOOD"

    # 2. Unknown → check VirusTotal
    vt_result = vt_check_host(host)

    if vt_result is None:
        return "UNKNOWN"

    if vt_result["malicious"] > 0:
        return "MALICIOUS"

    if vt_result["suspicious"] > 0:
        return "SUSPICIOUS"

    return "LIKELY_SAFE_BUT_UNKNOWN"

# ======================
# MAIN
# ======================
def main():
    hosts = extract_hosts(PCAP_FILE)

    print(f"\nExtracted Hosts: {len(hosts)}\n")

    for host in hosts:
        result = classify_host(host)

        print(f"{host} → {result}")

if __name__ == "__main__":
    main()
