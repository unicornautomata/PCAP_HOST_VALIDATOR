import pyshark
import requests
import pandas as pd
import csv
import os
import time

# =========================
# CONFIG
# =========================
VT_API_KEY = os.getenv("VT_API_KEY")  # DO NOT hardcode
PCAP_FILE = "capture.pcap"
KNOWN_HOSTS_FILE = "known_hosts.csv"
OUTPUT_FILE = "results.csv"

BASE_URL = "https://www.virustotal.com/api/v3"

headers = {
    "x-apikey": VT_API_KEY
}

# =========================
# VT CACHE (important for rate limits)
# =========================
vt_cache = {}

# =========================
# LOAD KNOWN HOSTS
# =========================
def load_known_hosts():
    try:
        df = pd.read_csv(KNOWN_HOSTS_FILE)
        return set(df["host"].str.lower())
    except Exception:
        return set()

known_hosts = load_known_hosts()

# =========================
# VIRUSTOTAL LOOKUP
# =========================
def vt_check_host(host):
    if host in vt_cache:
        return vt_cache[host]

    url = f"{BASE_URL}/domains/{host}"

    try:
        response = requests.get(url, headers=headers)

        # Rate limit handling
        if response.status_code == 429:
            print(f"[RATE LIMIT] VirusTotal throttled for {host}")
            return None

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        result = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }

        vt_cache[host] = result
        time.sleep(15)  # gentle delay for free tier

        return result

    except Exception as e:
        print(f"[ERROR] VirusTotal lookup failed for {host}: {e}")
        return None

# =========================
# PCAP HOST EXTRACTION
# =========================
def extract_hosts(pcap_file):
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)

    hosts = set()

    for packet in capture:
        try:
            # DNS
            if hasattr(packet, "dns") and hasattr(packet.dns, "qry_name"):
                hosts.add(packet.dns.qry_name.lower())

            # HTTP
            if hasattr(packet, "http") and hasattr(packet.http, "host"):
                hosts.add(packet.http.host.lower())

            # TLS SNI
            if hasattr(packet, "tls") and hasattr(packet.tls, "handshake_extensions_server_name"):
                hosts.add(packet.tls.handshake_extensions_server_name.lower())

        except Exception:
            continue

    return hosts

# =========================
# CLASSIFICATION ENGINE
# =========================
def classify_host(host):

    # 1. Known good baseline
    if host in known_hosts:
        return "KNOWN_GOOD"

    # 2. External intelligence check
    vt = vt_check_host(host)

    if vt is None:
        return "UNKNOWN"

    if vt["malicious"] > 0:
        return "MALICIOUS"

    if vt["suspicious"] > 0:
        return "SUSPICIOUS"

    return "LIKELY_SAFE_BUT_UNKNOWN"

# =========================
# SAVE RESULTS
# =========================
def save_results(results):
    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "classification"])

        for host, classification in results:
            writer.writerow([host, classification])

# =========================
# MAIN
# =========================
def main():
    print("\n[+] Starting SOC PCAP Analysis...\n")

    hosts = extract_hosts(PCAP_FILE)

    print(f"[+] Extracted {len(hosts)} unique hosts\n")

    results = []

    for host in hosts:
        classification = classify_host(host)
        print(f"{host} → {classification}")
        results.append((host, classification))

    save_results(results)

    print("\n[+] Analysis complete. Results saved to results.csv\n")

# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":
    main()
