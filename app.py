"""
app.py - Flask REST API backend.
Exposes endpoints for single-site analysis and two-site comparison.
"""

import os
import json
import traceback
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS

from capture import capture_packets
from extract import extract_features
from fingerprint import generate_fingerprint, compare_fingerprints

app = Flask(__name__)
CORS(app)

# Configuration
CAPTURE_DURATION = int(os.environ.get("CAPTURE_DURATION", 10))


# ──────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────

def _analyze_url(url: str) -> dict:
    """Full pipeline: capture → extract → fingerprint."""
    pcap_path = capture_packets(url, duration=CAPTURE_DURATION)

    if pcap_path is None:
        # Return empty fingerprint with error flag
        from extract import _empty_features
        features = _empty_features()
        fp = generate_fingerprint(url, features)
        fp["error"] = "No packets captured. Check permissions or try a different URL."
        return fp

    try:
        features = extract_features(pcap_path)
        fingerprint = generate_fingerprint(url, features)
    finally:
        # Clean up temp file
        try:
            os.remove(pcap_path)
        except Exception:
            pass

    return fingerprint


def _normalize_url(raw_url: str) -> str:
    """Normalize user-entered URLs into valid http(s) URLs."""
    url = (raw_url or "").strip().replace(" ", "")
    if not url:
        return ""

    if "://" not in url:
        url = f"https://{url}"

    parsed = urlparse(url)
    host = parsed.hostname
    if parsed.scheme not in ("http", "https") or not parsed.netloc or not host:
        return ""

    # Reject malformed values like https://https//example.com
    if parsed.path.startswith("//"):
        return ""

    if host.lower() in ("http", "https"):
        return ""

    return url


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    POST /api/analyze
    Body: { "url": "https://example.com" }
    Returns: fingerprint JSON
    """
    data = request.get_json(force=True, silent=True) or {}
    url = _normalize_url(data.get("url", ""))

    if not url:
        return jsonify({"error": "Invalid URL. Try something like https://example.com"}), 400

    try:
        fingerprint = _analyze_url(url)
        return jsonify(fingerprint)
    except OSError as e:
        traceback.print_exc()
        if getattr(e, "errno", None) == 22:
            return jsonify({
                "error": "Packet capture failed on this system interface (Windows/Npcap invalid argument). Try running as Administrator and retry."
            }), 500
        return jsonify({"error": str(e)}), 500
    except PermissionError:
        return jsonify({
            "error": "Permission denied. Run with sudo/admin privileges for packet capture."
        }), 403
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/compare", methods=["POST"])
def compare():
    """
    POST /api/compare
    Body: { "url1": "https://site1.com", "url2": "https://site2.com" }
    Returns: { "site1": fp1, "site2": fp2, "diff": diff }
    """
    data = request.get_json(force=True, silent=True) or {}
    url1 = _normalize_url(data.get("url1", ""))
    url2 = _normalize_url(data.get("url2", ""))

    if not url1 or not url2:
        return jsonify({"error": "Both URLs must be valid (example: https://example.com)"}), 400

    try:
        fp1 = _analyze_url(url1)
        fp2 = _analyze_url(url2)
        diff = compare_fingerprints(fp1, fp2)
        return jsonify({"site1": fp1, "site2": fp2, "diff": diff})
    except OSError as e:
        traceback.print_exc()
        if getattr(e, "errno", None) == 22:
            return jsonify({
                "error": "Packet capture failed on this system interface (Windows/Npcap invalid argument). Try running as Administrator and retry."
            }), 500
        return jsonify({"error": str(e)}), 500
    except PermissionError:
        return jsonify({
            "error": "Permission denied. Run with sudo/admin privileges for packet capture."
        }), 403
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/demo", methods=["GET"])
def demo():
    """Return a demo fingerprint for UI testing without actual capture."""
    import random, time

    def fake_fp(url, label, total_bytes, total_packets, unique_ips_n):
        sizes = [random.randint(40, 1500) for _ in range(total_packets)]
        hist = {"0-100": 0, "101-500": 0, "501-1000": 0, "1001-1500": 0, "1500+": 0}
        for s in sizes:
            if s <= 100: hist["0-100"] += 1
            elif s <= 500: hist["101-500"] += 1
            elif s <= 1000: hist["501-1000"] += 1
            elif s <= 1500: hist["1001-1500"] += 1
            else: hist["1500+"] += 1

        timeline = [{"second": i, "bytes": random.randint(1000, total_bytes // 10)}
                    for i in range(10)]

        from classify import get_label_color, get_label_icon
        return {
            "site_url": url,
            "capture_timestamp": "2024-01-01T12:00:00+00:00",
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_bytes_human": f"{total_bytes // 1024} KB",
            "top_protocol": "HTTPS",
            "unique_ips": [f"104.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
                           for _ in range(unique_ips_n)],
            "unique_ip_count": unique_ips_n,
            "dns_queries": ["cdn.example.com", "api.example.com", "fonts.googleapis.com"],
            "mean_packet_size": round(sum(sizes) / len(sizes), 2),
            "min_packet_size": min(sizes),
            "max_packet_size": max(sizes),
            "session_duration": round(random.uniform(4, 12), 3),
            "mean_inter_arrival_ms": round(random.uniform(0.5, 50), 3),
            "protocol_distribution": {"HTTPS": 68.5, "TCP": 12.3, "DNS": 8.4, "UDP": 6.8, "ICMP": 2.1, "ARP": 1.9},
            "size_histogram": hist,
            "traffic_timeline": timeline,
            "behavior_label": label,
            "behavior_confidence": random.randint(70, 92),
            "behavior_color": get_label_color(label),
            "behavior_icon": get_label_icon(label),
        }

    fp1 = fake_fp("https://youtube.com", "Streaming", 2_400_000, 1850, 12)
    fp2 = fake_fp("https://example.com", "Static Content", 48_000, 62, 3)
    diff = compare_fingerprints(fp1, fp2)
    return jsonify({"site1": fp1, "site2": fp2, "diff": diff})


if __name__ == "__main__":
    print("=" * 60)
    print("  Network Fingerprint Analyzer")
    print("  Run with: sudo python app.py")
    print("  Open: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
