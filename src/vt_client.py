import requests
import os

BASE_URL = "https://www.virustotal.com/api/v3"
API_KEY = os.getenv("VT_API_KEY")

headers = {
    "x-apikey": API_KEY
}

vt_cache = {}

def vt_check_host(host):

    if host in vt_cache:
        return vt_cache[host]

    url = f"{BASE_URL}/domains/{host}"

    try:
        r = requests.get(url, headers=headers)

        if r.status_code == 429:
            return None

        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        vt_cache[host] = stats
        return stats

    except:
        return None
