import pyshark

def extract_hosts(pcap_file):
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)

    hosts = set()

    for packet in capture:
        try:
            if hasattr(packet, "dns") and hasattr(packet.dns, "qry_name"):
                hosts.add(packet.dns.qry_name.lower())

            if hasattr(packet, "http") and hasattr(packet.http, "host"):
                hosts.add(packet.http.host.lower())

            if hasattr(packet, "tls") and hasattr(packet.tls, "handshake_extensions_server_name"):
                hosts.add(packet.tls.handshake_extensions_server_name.lower())

        except:
            continue

    return hosts
