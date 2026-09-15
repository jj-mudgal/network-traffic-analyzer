# Architecture

## 1. Overview

The Network Traffic Analyzer follows a simple linear pipeline architecture, chosen to keep the system understandable and modular enough for a 5-person team to work on independently within 6 one-week sprints.

```
Network Interface
  → Scapy Packet Capture
  → Packet Parser
  → Backend / Flask
  → SQLite Database
  → Dashboard
```

Security detection runs on analyzed packet information (stored or in-flight metadata) and writes alerts that are stored and displayed through the same application.

## 2. Design Principles

- Keep the architecture modular enough that different team members can work independently.
- Store packet **metadata**, not full payloads.
- Favor a simple, explainable pipeline over a distributed or service-oriented design.
- No new frameworks/technologies outside the agreed stack (see README) without team agreement.

## 3. Modules

> Exact filenames/module boundaries are finalized as the team implements them — check existing code before creating new files.

| Module | Responsibility |
|---|---|
| Packet capture | Interfaces with Scapy to capture live packets from a chosen network interface |
| Packet parsing | Extracts metadata (IPs, ports, protocol, size, TCP flags, timestamp) from captured packets |
| Backend / API | Flask app exposing endpoints for packet data, statistics, filters, and alerts |
| Database | SQLite schema and access layer for `packets` and `security_alerts` |
| Security detection | Rule-based logic for possible port scan and abnormal traffic detection |
| Frontend / dashboard | HTML/CSS/JS dashboard consuming the API, rendering the packet table, filters, and Chart.js visualizations |
| Tests | Pytest (unit/integration) and Playwright (UI) test suites |

## 4. Data Flow (Detailed)

1. **Capture** — Scapy listens on the selected interface and yields raw packets.
2. **Parse** — Each packet is parsed into a metadata record: packet ID, timestamp, source/destination IP, source/destination port, protocol, packet size, TCP flags.
3. **Store** — The metadata record is written to the SQLite `packets` table via parameterized queries.
4. **Detect** — Security detection logic evaluates incoming/stored metadata against configurable rules (port scan, traffic rate) and writes matches to `security_alerts`.
5. **Serve** — The Flask backend exposes REST endpoints for packet listing/filtering, statistics, and alerts.
6. **Display** — The dashboard fetches from the API and renders the packet table, filters/search, Chart.js visualizations, and the alert list.

## 5. Database Schema (Conceptual)

Schema may be adjusted during implementation as technically necessary; changes should be reflected here.

### `packets`

| Field | Notes |
|---|---|
| `id` | Primary key |
| `timestamp` | Capture time |
| `source_ip` | |
| `destination_ip` | |
| `source_port` | |
| `destination_port` | |
| `protocol` | TCP / UDP / ICMP |
| `packet_size` | Bytes |
| `tcp_flags` | Where applicable |

### `security_alerts`

| Field | Notes |
|---|---|
| `id` | Primary key |
| `timestamp` | Alert generation time |
| `source_ip` | Source IP that triggered the alert |
| `alert_type` | e.g. "Possible Port Scan", "Abnormal Traffic" |
| `severity` | e.g. Low / Medium / High |
| `description` | Human-readable explanation, worded cautiously (never claims a confirmed attack) |

## 6. Security Detection Logic

### 6.1 Possible Port Scan
Triggered when a single source IP attempts connections to an unusually large number of distinct destination ports within a configurable time window. Wording used: "Possible Port Scan".

### 6.2 Abnormal Traffic
Triggered when traffic rate (packets/time) exceeds a configurable threshold. Wording used: "Suspicious Traffic" / "Abnormal Traffic".

Both are rule-based and explicitly acknowledged as capable of false positives/negatives — this is documented, not hidden.

## 7. Non-Goals

Explicitly out of the architecture for this project (see `requirements.md` §5 for full list): ML/DL-based detection, SDN, blockchain, complex IDS/IPS, distributed systems, Kubernetes, microservices, cloud infrastructure, advanced payload inspection.
