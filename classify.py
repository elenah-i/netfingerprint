"""
classify.py - Rule-based website behavior classifier.
Assigns a behavioral label and confidence score based on fingerprint features.
"""


def classify(features: dict) -> tuple[str, int]:
    """
    Classify website behavior from extracted features.

    Args:
        features: Feature dictionary from extract.py.

    Returns:
        Tuple of (label, confidence_percent).
    """
    total_bytes = features.get("total_bytes", 0)
    mean_size = features.get("mean_packet_size", 0)
    total_packets = features.get("total_packets", 0)
    unique_ips = len(features.get("unique_ips", []))
    dns_count = len(features.get("dns_queries", []))
    distribution = features.get("protocol_distribution", {})
    session_duration = features.get("session_duration", 0)
    mean_iat = features.get("mean_inter_arrival", 0)

    https_pct = distribution.get("HTTPS", 0)
    tcp_pct = distribution.get("TCP", 0)
    udp_pct = distribution.get("UDP", 0)
    dns_pct = distribution.get("DNS", 0)

    scores = {}

    # --- Streaming ---
    # Large bytes, large packets, heavy TCP/HTTPS
    stream_score = 0
    if total_bytes > 500_000:
        stream_score += 35
    elif total_bytes > 100_000:
        stream_score += 15
    if mean_size > 800:
        stream_score += 30
    elif mean_size > 400:
        stream_score += 15
    if (tcp_pct + https_pct) > 70:
        stream_score += 20
    if udp_pct > 30:  # UDP streaming (WebRTC)
        stream_score += 15
    if total_packets > 500:
        stream_score += 10
    scores["Streaming"] = stream_score

    # --- Social Media ---
    # Many unique IPs, frequent small packets, mixed protocols
    social_score = 0
    if unique_ips > 10:
        social_score += 30
    elif unique_ips > 5:
        social_score += 15
    if mean_size < 400:
        social_score += 20
    if dns_count > 8:
        social_score += 20
    elif dns_count > 4:
        social_score += 10
    if 100 < total_packets < 800:
        social_score += 15
    if dns_pct > 5:
        social_score += 15
    scores["Social Media"] = social_score

    # --- Static Content ---
    # Low packet count, short session, few DNS queries, small data
    static_score = 0
    if total_packets < 100:
        static_score += 35
    elif total_packets < 200:
        static_score += 15
    if total_bytes < 50_000:
        static_score += 25
    elif total_bytes < 200_000:
        static_score += 10
    if dns_count <= 3:
        static_score += 20
    if session_duration < 5:
        static_score += 20
    scores["Static Content"] = static_score

    # --- API-Heavy ---
    # Very small packets, rapid request/response, HTTPS dominant
    api_score = 0
    if mean_size < 300:
        api_score += 30
    elif mean_size < 500:
        api_score += 15
    if https_pct > 60:
        api_score += 25
    if mean_iat < 0.05 and mean_iat > 0:
        api_score += 25
    elif mean_iat < 0.2 and mean_iat > 0:
        api_score += 10
    if 50 < total_packets < 400:
        api_score += 20
    scores["API-Heavy"] = api_score

    if not scores:
        return "Unknown", 0

    best_label = max(scores, key=scores.get)
    best_score = scores[best_label]

    # Normalize confidence: cap at 95%
    confidence = min(int((best_score / 100) * 100), 95)
    if best_score < 20:
        return "Unknown", confidence

    return best_label, confidence


def get_label_color(label: str) -> str:
    """Return a hex color for each behavior label."""
    colors = {
        "Streaming": "#FF6B35",
        "Social Media": "#9B5DE5",
        "Static Content": "#00BBF9",
        "API-Heavy": "#00F5D4",
        "Unknown": "#888888",
    }
    return colors.get(label, "#888888")


def get_label_icon(label: str) -> str:
    """Return an emoji icon for each behavior label."""
    icons = {
        "Streaming": "📺",
        "Social Media": "🌐",
        "Static Content": "📄",
        "API-Heavy": "⚡",
        "Unknown": "❓",
    }
    return icons.get(label, "❓")
