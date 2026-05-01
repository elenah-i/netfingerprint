"""
capture.py - Network packet capture module using Scapy.
Sniffs packets on the active interface while generating traffic to the target URL.
"""

import threading
import time
import socket
import requests
import os
import tempfile
from scapy.all import sniff, wrpcap, conf

# Suppress Scapy warnings
conf.verb = 0


def resolve_host(url: str) -> list[str]:
    """Resolve the hostname of a URL to its IP addresses."""
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
        if not hostname:
            return []
        results = socket.getaddrinfo(hostname, None)
        ips = list(set(r[4][0] for r in results))
        return ips
    except Exception as e:
        print(f"[capture] DNS resolution failed: {e}")
        return []


def _fetch_url(url: str, timeout: int = 15):
    """Make an HTTP(S) request to generate real traffic."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }
    try:
        # Delay slightly so sniffer is ready
        time.sleep(1.5)
        response = requests.get(url, headers=headers, timeout=timeout, verify=False)
        print(f"[capture] Fetched {url} -> HTTP {response.status_code}")
    except requests.exceptions.SSLError:
        try:
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            print(f"[capture] Fetched {url} (no SSL verify) -> HTTP {response.status_code}")
        except Exception as e:
            print(f"[capture] Fetch error (SSL fallback): {e}")
    except Exception as e:
        print(f"[capture] Fetch error: {e}")


def capture_packets(url: str, duration: int = 10, interface: str = None) -> str:
    """
    Capture network packets while fetching the target URL.

    Args:
        url: The target website URL.
        duration: Capture window in seconds (default 10).
        interface: Network interface to sniff on. Auto-detected if None.

    Returns:
        Path to the saved .pcap file, or None on failure.
    """
    # Resolve target IPs for filtering
    target_ips = resolve_host(url)
    print(f"[capture] Resolved IPs for {url}: {target_ips}")

    # Auto-detect interface
    if interface is None:
        try:
            interface = conf.iface
        except Exception:
            interface = None
    print(f"[capture] Using interface: {interface}")

    # Build BPF filter – capture all traffic if no IPs resolved
    if target_ips:
        ip_filters = " or ".join(f"host {ip}" for ip in target_ips)
        bpf_filter = f"({ip_filters}) or port 53"
    else:
        bpf_filter = "ip"

    # Packet storage
    captured_packets = []

    def packet_handler(pkt):
        captured_packets.append(pkt)

    # Start fetch in background thread
    fetch_thread = threading.Thread(target=_fetch_url, args=(url,), daemon=True)
    fetch_thread.start()

    # Sniff packets
    print(f"[capture] Sniffing for {duration}s on {interface} with filter: {bpf_filter}")
    try:
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=packet_handler,
            timeout=duration,
            store=False
        )
    except Exception as e:
        print(f"[capture] Sniff error: {e}")
        # Fall back: sniff without filter
        try:
            sniff(
                filter="ip",
                prn=packet_handler,
                timeout=duration,
                store=False
            )
        except Exception as e2:
            print(f"[capture] Fallback sniff error: {e2}")

    fetch_thread.join(timeout=5)

    # Save to temp pcap file
    if not captured_packets:
        print("[capture] No packets captured.")
        return None

    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        pcap_path = tmp.name
        tmp.close()
        wrpcap(pcap_path, captured_packets)
        print(f"[capture] Saved {len(captured_packets)} packets -> {pcap_path}")
        return pcap_path
    except Exception as e:
        print(f"[capture] Save error: {e}")
        return None
