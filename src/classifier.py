def classify_host(host, vt_result, known_hosts):

    if host in known_hosts:
        return "KNOWN_GOOD"

    if vt_result is None:
        return "UNKNOWN"

    if vt_result.get("malicious", 0) > 0:
        return "MALICIOUS"

    if vt_result.get("suspicious", 0) > 0:
        return "SUSPICIOUS"

    return "LIKELY_SAFE_BUT_UNKNOWN"
