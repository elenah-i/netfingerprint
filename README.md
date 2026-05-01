# NetPrint — Network Fingerprint Analyzer

An educational web tool that captures live network traffic, analyzes packets,
and generates a unique **behavioral fingerprint** for any website.

---

## Project Structure

```
netfingerprint/
├── app.py            ← Flask REST API (routes: /api/analyze, /api/compare, /api/demo)
├── capture.py        ← Scapy packet sniffer + URL fetcher
├── extract.py        ← Feature extraction from .pcap files
├── fingerprint.py    ← Fingerprint assembly & comparison diff
├── classify.py       ← Rule-based behavior classifier
├── requirements.txt  ← Python dependencies
└── templates/
    └── index.html    ← Single-page frontend (Chart.js visualizations)
```

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

> Scapy requires libpcap. On Linux: `sudo apt install libpcap-dev`
> On macOS: `brew install libpcap`

### 2. Run the Server (requires root for packet capture)

```bash
sudo python app.py
```

Open your browser at: **http://localhost:5000**

---

## API Endpoints

### `POST /api/analyze`
Analyze a single website.

**Request body:**
```json
{ "url": "https://example.com" }
```

**Response:** Full fingerprint JSON with protocol distribution, packet stats, and behavior label.

---

### `POST /api/compare`
Compare two websites side by side.

**Request body:**
```json
{ "url1": "https://youtube.com", "url2": "https://example.com" }
```

**Response:**
```json
{
  "site1": { ...fingerprint... },
  "site2": { ...fingerprint... },
  "diff": { ...comparison metrics... }
}
```

---

### `GET /api/demo`
Returns pre-generated demo data (no capture needed, for UI testing).

---

## Fingerprint JSON Schema

```json
{
  "site_url": "https://example.com",
  "capture_timestamp": "2024-01-01T12:00:00+00:00",
  "total_packets": 142,
  "total_bytes": 48500,
  "total_bytes_human": "47.4 KB",
  "top_protocol": "HTTPS",
  "unique_ips": ["93.184.216.34"],
  "unique_ip_count": 1,
  "dns_queries": ["example.com"],
  "mean_packet_size": 341.5,
  "min_packet_size": 54,
  "max_packet_size": 1460,
  "session_duration": 4.21,
  "mean_inter_arrival_ms": 29.5,
  "protocol_distribution": {
    "HTTPS": 72.5, "TCP": 15.2, "DNS": 8.1, "UDP": 4.2
  },
  "size_histogram": {
    "0-100": 28, "101-500": 54, "501-1000": 31, "1001-1500": 29, "1500+": 0
  },
  "traffic_timeline": [
    { "second": 0, "bytes": 4200 },
    { "second": 1, "bytes": 18400 }
  ],
  "behavior_label": "Static Content",
  "behavior_confidence": 78,
  "behavior_color": "#00BBF9",
  "behavior_icon": "📄"
}
```

---

## Behavior Labels

| Label | Characteristics |
|-------|----------------|
| 📺 Streaming | High byte volume, large packets, heavy TCP/UDP |
| 🌐 Social Media | Many unique IPs, mixed protocols, frequent DNS |
| 📄 Static Content | Low packet count, short session, minimal DNS |
| ⚡ API-Heavy | Small packets, rapid cycles, HTTPS dominant |
| ❓ Unknown | Does not match any pattern |

---

## Configuration

Set the capture duration via environment variable (default: 10 seconds):

```bash
sudo CAPTURE_DURATION=15 python app.py
```

---

## Requirements

- Python 3.10+
- Root/admin privileges (for raw socket packet capture)
- Linux or macOS (Scapy raw sockets)
- Modern browser (Chrome, Firefox, Edge)

---

## Educational Use

This tool is designed for networking students to:
- Observe real-world protocol distributions
- Compare traffic profiles of different website types
- Understand packet size patterns and request frequency
- Visually differentiate streaming vs. static vs. API-heavy sites
