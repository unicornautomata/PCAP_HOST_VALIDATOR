import os
from dotenv import load_dotenv

from src.pcap_parser import extract_hosts
from src.vt_client import vt_check_host
from src.classifier import classify_host
from src.storage import save_results

import pandas as pd

load_dotenv()

# ======================
# LOAD KNOWN HOSTS
# ======================
def load_known_hosts():
    try:
        df = pd.read_csv("data/known_hosts.csv")
        return set(df["host"].str.lower())
    except:
        return set()

known_hosts = load_known_hosts()

# ======================
# MAIN WORKFLOW
# ======================
def main():

    print("[+] Starting SOC PCAP Analysis...\n")

    hosts = extract_hosts("data/capture.pcap")

    print(f"[+] Extracted {len(hosts)} hosts\n")

    results = []

    for host in hosts:

        vt_result = vt_check_host(host)
        classification = classify_host(host, vt_result, known_hosts)

        print(f"{host} → {classification}")

        results.append((host, classification))

    save_results(results)

    print("\n[+] Done. Results saved to reports/results.csv")

# ======================
if __name__ == "__main__":
    main()
