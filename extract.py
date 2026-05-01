"""
extract.py - Feature extraction module.
Reads a .pcap file and computes all statistical features needed for fingerprinting.
"""

from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP, ARP
from scapy.layers.http import HTTP
import statistics


def extract_features(pcap_path: str) -> dict:
    """
    Parse a .pcap file and extract networking features.

    Args:
        pcap_path: Path to the .pcap file.

    Returns:
        Dictionary of extracted features.
    """
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[extract] Failed to read pcap: {e}")
        return _empty_features()

    if not packets:
        return _empty_features()

    total_packets = len(packets)
    sizes = []
    timestamps = []
    dst_ips = set()
    dns_queries = []
    protocol_counts = {
        "TCP": 0,
        "UDP": 0,
        "DNS": 0,
        "ICMP": 0,
        "ARP": 0,
        "HTTPS": 0,
        "Other": 0,
    }
    bytes_per_second = {}  # second_bucket → bytes

    for pkt in packets:
        # Packet size
        size = len(pkt)
        sizes.append(size)

        # Timestamp
        ts = float(pkt.time)
        timestamps.append(ts)

        # Bytes per second bucket
        bucket = int(ts)
        bytes_per_second[bucket] = bytes_per_second.get(bucket, 0) + size

        # Destination IP
        if IP in pkt:
            dst_ips.add(pkt[IP].dst)

        # Protocol detection (order matters – most specific first)
        if DNS in pkt:
            protocol_counts["DNS"] += 1
            # Extract DNS query names
            try:
                if pkt[DNS].qd:
                    qname = pkt[DNS].qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="ignore").rstrip(".")
                    if qname and qname not in dns_queries:
                        dns_queries.append(qname)
            except Exception:
                pass
        elif ARP in pkt:
            protocol_counts["ARP"] += 1
        elif ICMP in pkt:
            protocol_counts["ICMP"] += 1
        elif TCP in pkt:
            # Check for HTTPS (port 443)
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            if src_port == 443 or dst_port == 443:
                protocol_counts["HTTPS"] += 1
            else:
                protocol_counts["TCP"] += 1
        elif UDP in pkt:
            protocol_counts["UDP"] += 1
        else:
            protocol_counts["Other"] += 1

    # Inter-arrival times
    inter_arrival_times = []
    if len(timestamps) > 1:
        sorted_ts = sorted(timestamps)
        inter_arrival_times = [
            sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)
        ]

    # Total bytes
    total_bytes = sum(sizes)

    # Packet size stats
    mean_size = statistics.mean(sizes) if sizes else 0
    min_size = min(sizes) if sizes else 0
    max_size = max(sizes) if sizes else 0

    # Size histogram buckets
    size_histogram = {"0-100": 0, "101-500": 0, "501-1000": 0, "1001-1500": 0, "1500+": 0}
    for s in sizes:
        if s <= 100:
            size_histogram["0-100"] += 1
        elif s <= 500:
            size_histogram["101-500"] += 1
        elif s <= 1000:
            size_histogram["501-1000"] += 1
        elif s <= 1500:
            size_histogram["1001-1500"] += 1
        else:
            size_histogram["1500+"] += 1

    # Protocol percentages
    protocol_distribution = {}
    total_proto = sum(protocol_counts.values())
    for proto, count in protocol_counts.items():
        if total_proto > 0:
            protocol_distribution[proto] = round((count / total_proto) * 100, 2)
        else:
            protocol_distribution[proto] = 0.0

    # Traffic timeline (bytes per second, normalized to relative seconds)
    traffic_timeline = []
    if bytes_per_second:
        min_bucket = min(bytes_per_second.keys())
        max_bucket = max(bytes_per_second.keys())
        for sec in range(min_bucket, max_bucket + 1):
            traffic_timeline.append({
                "second": sec - min_bucket,
                "bytes": bytes_per_second.get(sec, 0)
            })

    # Session duration
    if timestamps:
        duration = max(timestamps) - min(timestamps)
    else:
        duration = 0.0

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "mean_packet_size": round(mean_size, 2),
        "min_packet_size": min_size,
        "max_packet_size": max_size,
        "packet_sizes": sizes,
        "protocol_counts": protocol_counts,
        "protocol_distribution": protocol_distribution,
        "unique_ips": list(dst_ips),
        "dns_queries": dns_queries[:20],  # cap for display
        "inter_arrival_times": inter_arrival_times[:100],  # cap for JSON size
        "size_histogram": size_histogram,
        "traffic_timeline": traffic_timeline,
        "session_duration": round(duration, 3),
        "mean_inter_arrival": round(statistics.mean(inter_arrival_times), 6)
            if inter_arrival_times else 0,
    }


def _empty_features() -> dict:
    return {
        "total_packets": 0,
        "total_bytes": 0,
        "mean_packet_size": 0,
        "min_packet_size": 0,
        "max_packet_size": 0,
        "packet_sizes": [],
        "protocol_counts": {},
        "protocol_distribution": {},
        "unique_ips": [],
        "dns_queries": [],
        "inter_arrival_times": [],
        "size_histogram": {"0-100": 0, "101-500": 0, "501-1000": 0, "1001-1500": 0, "1500+": 0},
        "traffic_timeline": [],
        "session_duration": 0,
        "mean_inter_arrival": 0,
    }
