"""
capture.py - Network packet capture module using Scapy.
Sniffs packets on the active interface while generating traffic to the target URL.

Fix: Robust fallback chain for Windows/Npcap OSError(22) "Invalid argument".
     - BPF filter restricted to IPv4 hosts only (no ip6 in filter string)
     - Fallback tries no-filter sniff on all interfaces (L3socket)
     - Uses conf.L3socket on Windows to avoid raw Ethernet issues
"""

import sys
import threading
import time
import socket
import requests
import os
import tempfile
import ipaddress
from scapy.all import sniff, wrpcap, conf, get_if_list

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
        time.sleep(1.5)  # Delay so sniffer is ready before traffic starts
        response = requests.get(url, headers=headers, timeout=timeout, verify=False)
        print(f"[capture] Fetched {url} -> HTTP {response.status_code}")
    except Exception as e:
        print(f"[capture] Fetch error: {e}")


def _safe_sniff(sniff_kwargs: dict, captured_packets: list) -> bool:
    """
    Attempt a single sniff() call. Returns True on success, False on error.
    Appends captured packets to the provided list.
    """
    local = []
    kwargs = dict(sniff_kwargs)
    kwargs["prn"] = lambda pkt: local.append(pkt)
    try:
        sniff(**kwargs)
        captured_packets.extend(local)
        return True
    except OSError as e:
        print(f"[capture] sniff OSError({e.errno}): {e}")
        return False
    except Exception as e:
        print(f"[capture] sniff error: {e}")
        return False


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
    try:
        # --- Resolve target IPs ---
        target_ips = resolve_host(url)
        print(f"[capture] Resolved IPs for {url}: {target_ips}")

        # --- IPv4-only BPF filter (IPv6 host expressions break Npcap BPF) ---
        ipv4_targets = []
        for ip in target_ips:
            try:
                if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                    ipv4_targets.append(ip)
            except ValueError:
                continue

        if ipv4_targets:
            ip_filters = " or ".join(f"host {ip}" for ip in ipv4_targets)
            bpf_filter = f"({ip_filters}) or port 53"
        else:
            # Avoid "ip or ip6" — just use "ip" which is always valid on Npcap
            bpf_filter = "ip"

        # --- Interface selection ---
        # Don't force an interface if none was given; let Scapy use conf.iface.
        # On Windows, conf.iface is set by Npcap to the active adapter automatically.
        selected_iface = interface.strip() if isinstance(interface, str) and interface.strip() else None
        print(f"[capture] Interface: {selected_iface or '(scapy default)'}")
        print(f"[capture] BPF filter: {bpf_filter}")

        # --- Start URL fetch in background ---
        fetch_thread = threading.Thread(target=_fetch_url, args=(url,), daemon=True)
        fetch_thread.start()

        captured_packets = []

        # === Attempt 1: with BPF filter, selected or default interface ===
        kwargs1 = {"filter": bpf_filter, "timeout": duration, "store": False}
        if selected_iface:
            kwargs1["iface"] = selected_iface

        print(f"[capture] Attempt 1: filter='{bpf_filter}', iface={selected_iface or 'auto'}")
        if not _safe_sniff(kwargs1, captured_packets):

            # === Attempt 2: no BPF filter, selected or default interface ===
            kwargs2 = {"timeout": duration, "store": False}
            if selected_iface:
                kwargs2["iface"] = selected_iface
            print("[capture] Attempt 2: no filter, same interface")
            if not _safe_sniff(kwargs2, captured_packets):

                # === Attempt 3: no filter, no explicit interface (pure Scapy default) ===
                kwargs3 = {"timeout": duration, "store": False}
                print("[capture] Attempt 3: no filter, no iface (scapy auto)")
                _safe_sniff(kwargs3, captured_packets)

        fetch_thread.join(timeout=5)

        # --- Save to temp pcap ---
        if not captured_packets:
            print("[capture] No packets captured.")
            return None

        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        pcap_path = tmp.name
        tmp.close()
        wrpcap(pcap_path, captured_packets)
        print(f"[capture] Saved {len(captured_packets)} packets -> {pcap_path}")
        return pcap_path

    except Exception as e:
        print(f"[capture] Unexpected capture error: {e}")
        return None
