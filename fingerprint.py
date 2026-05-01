"""
fingerprint.py - Fingerprint assembly module.
Packages extracted features into a structured JSON fingerprint object.
"""

from datetime import datetime, timezone
from classify import classify, get_label_color, get_label_icon


def generate_fingerprint(url: str, features: dict) -> dict:
    """
    Assemble a structured network fingerprint from extracted features.

    Args:
        url: The target website URL.
        features: Feature dictionary from extract.py.

    Returns:
        Structured fingerprint dictionary (JSON-serializable).
    """
    # Determine top protocol by count
    protocol_distribution = features.get("protocol_distribution", {})
    if protocol_distribution:
        top_protocol = max(protocol_distribution, key=protocol_distribution.get)
        if protocol_distribution[top_protocol] == 0:
            top_protocol = "Unknown"
    else:
        top_protocol = "Unknown"

    # Classify behavior
    behavior_label, confidence = classify(features)

    fingerprint = {
        "site_url": url,
        "capture_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_packets": features.get("total_packets", 0),
        "total_bytes": features.get("total_bytes", 0),
        "total_bytes_human": _human_bytes(features.get("total_bytes", 0)),
        "top_protocol": top_protocol,
        "unique_ips": features.get("unique_ips", []),
        "unique_ip_count": len(features.get("unique_ips", [])),
        "dns_queries": features.get("dns_queries", []),
        "mean_packet_size": features.get("mean_packet_size", 0),
        "min_packet_size": features.get("min_packet_size", 0),
        "max_packet_size": features.get("max_packet_size", 0),
        "session_duration": features.get("session_duration", 0),
        "mean_inter_arrival_ms": round(features.get("mean_inter_arrival", 0) * 1000, 3),
        "protocol_distribution": protocol_distribution,
        "size_histogram": features.get("size_histogram", {}),
        "traffic_timeline": features.get("traffic_timeline", []),
        "behavior_label": behavior_label,
        "behavior_confidence": confidence,
        "behavior_color": get_label_color(behavior_label),
        "behavior_icon": get_label_icon(behavior_label),
    }

    return fingerprint


def compare_fingerprints(fp1: dict, fp2: dict) -> dict:
    """
    Generate a diff object comparing two fingerprints.

    Args:
        fp1: First fingerprint.
        fp2: Second fingerprint.

    Returns:
        Dictionary of comparison results with direction indicators.
    """
    def compare_metric(key, label, higher_is="neutral", format_fn=None):
        v1 = fp1.get(key, 0)
        v2 = fp2.get(key, 0)
        if format_fn:
            d1 = format_fn(v1)
            d2 = format_fn(v2)
        else:
            d1 = v1
            d2 = v2

        if v1 > v2:
            direction = "site1_higher"
        elif v2 > v1:
            direction = "site2_higher"
        else:
            direction = "equal"

        diff_pct = 0
        if v1 and v2:
            diff_pct = round(abs(v1 - v2) / max(v1, v2) * 100, 1)

        return {
            "label": label,
            "site1": d1,
            "site2": d2,
            "direction": direction,
            "diff_pct": diff_pct,
            "higher_is": higher_is,
        }

    return {
        "total_bytes": compare_metric("total_bytes", "Total Data", format_fn=_human_bytes),
        "total_packets": compare_metric("total_packets", "Packet Count"),
        "unique_ip_count": compare_metric("unique_ip_count", "Unique IPs"),
        "mean_packet_size": compare_metric("mean_packet_size", "Avg Packet Size (bytes)"),
        "max_packet_size": compare_metric("max_packet_size", "Max Packet Size (bytes)"),
        "session_duration": compare_metric("session_duration", "Session Duration (s)"),
        "mean_inter_arrival_ms": compare_metric("mean_inter_arrival_ms", "Avg Inter-arrival (ms)"),
        "behavior_label_1": fp1.get("behavior_label", "Unknown"),
        "behavior_label_2": fp2.get("behavior_label", "Unknown"),
        "top_protocol_1": fp1.get("top_protocol", "Unknown"),
        "top_protocol_2": fp2.get("top_protocol", "Unknown"),
    }


def _human_bytes(b: int) -> str:
    """Convert bytes to human-readable string."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b / 1024 ** 2:.1f} MB"
    else:
        return f"{b / 1024 ** 3:.1f} GB"
