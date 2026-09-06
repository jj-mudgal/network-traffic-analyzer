# Network Traffic Analyzer

A web-based project inspired by the basic functionality of Wireshark. It captures network packets from an authorized network interface, extracts useful packet metadata, stores it, displays it through a web dashboard, and provides basic traffic analysis and security alerts.

> This project is **not** intended to replace Wireshark. It is an educational, student-built network monitoring and analysis tool with basic security detection.

**Status:** Sprint 1 of 6 — Project Setup & Basic Capture (in progress)

---

## 1. Project Overview

- **Repository:** `network-traffic-analyzer`
- **Type:** College Computer Networks project (student team)
- **Team size:** 5 members
- **Duration:** 6 weeks, run as 6 one-week Agile sprints

**Main project flow:**

```
Capture → Analyze → Store → Display → Filter/Visualize → Detect Basic Suspicious Activity → Test
```

## 2. Objectives

1. Capture network packets in real time.
2. Extract basic packet information.
3. Store packet metadata in a database.
4. Display captured traffic through a web dashboard.
5. Allow users to filter and search traffic.
6. Provide basic traffic statistics and visualizations.
7. Detect simple suspicious traffic patterns.
8. Generate basic security alerts.
9. Be tested using automated testing tools.
10. Be developed using an Agile sprint-based workflow.

## 3. Features (target, by end of project)

- Real-time packet capture from a selected network interface
- Packet metadata extraction (IPs, ports, protocol, size, TCP flags)
- SQLite-backed storage of packet metadata (not payloads)
- Web dashboard with a searchable/filterable packet table
- Protocol (TCP/UDP/ICMP), IP, and port filtering
- Traffic statistics and charts (Chart.js)
- Basic security detection: possible port scan, abnormal traffic rate
- Security alert history in the dashboard

## 4. Technology Stack

| Area | Technology |
|---|---|
| Backend | Python, Flask |
| Packet capture/analysis | Scapy |
| Frontend | HTML, CSS, JavaScript |
| Charts | Chart.js |
| Database | SQLite |
| Testing (unit/integration) | Pytest |
| Testing (UI) | Playwright |
| Version control | Git, GitHub |
| Project management | GitHub Projects |

## 5. Requirements

See [`docs/requirements.md`](docs/requirements.md) for functional and non-functional requirements.

- Python 3.10+
- `pip` for dependency management
- Administrator/root privileges (required by Scapy for raw packet capture)
- A network interface you are authorized to capture traffic on

## 6. Project Structure

> Exact filenames are finalized as the team implements them — this is the intended Sprint 1 structure.

```
network-traffic-analyzer/
├── app/
│   ├── __init__.py
│   ├── capture/          # Scapy packet capture + parsing
│   ├── models/           # Database models / schema
│   ├── api/              # Flask routes / API endpoints
│   └── security/         # Detection rules (port scan, abnormal traffic)
├── static/               # CSS, JS, Chart.js dashboard assets
├── templates/             # HTML templates (dashboard)
├── tests/
│   ├── unit/
│   ├── integration/
│   └── ui/                # Playwright tests
├── docs/
│   ├── requirements.md
│   ├── architecture.md
│   ├── testing.md
│   └── sprint-plan.md
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## 7. Installation

```bash
# Clone the repository
git clone https://github.com/<org>/network-traffic-analyzer.git
cd network-traffic-analyzer

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in any required configuration (no secrets are committed to the repo).

## 8. How to Run

> Packet capture requires elevated privileges (Scapy needs raw socket access).

```bash
# Run the Flask app (adjust once app entrypoint is finalized)
sudo python -m flask run
```

Then open the dashboard at `http://localhost:5000`.

## 9. How the System Works

```
Network Interface
  → Scapy Packet Capture
  → Packet Parser
  → Backend / Flask
  → SQLite Database
  → Dashboard
```

1. Scapy captures live packets on the selected interface.
2. The parser extracts metadata (IPs, ports, protocol, size, TCP flags, timestamp).
3. Metadata is written to the SQLite `packets` table.
4. The Flask API serves packet and statistics data to the dashboard.
5. The dashboard displays the packet table, filters, and charts.
6. Security detection logic runs against stored/incoming metadata and writes to `security_alerts` when rules are triggered.

## 10. Database

**Engine:** SQLite. The system stores packet **metadata only** — not full packet payloads.

See [`docs/architecture.md`](docs/architecture.md) for schema details.

## 11. Security Features

Only basic, explainable detection is in scope for this project:

- **Possible Port Scan Detection** — flags a source IP that attempts connections to an unusually large number of distinct ports within a configurable time window.
- **Abnormal Traffic Detection** — flags traffic rates exceeding a configurable threshold.

Alerts use cautious wording ("Possible Port Scan", "Suspicious Traffic", "Abnormal Traffic") — an alert is never presented as a confirmed attack, since rule-based detection can produce false positives and false negatives.

## 12. Testing

- **Unit testing (Pytest):** packet parsing, IP extraction, protocol identification, timestamp/size extraction, database operations, security detection logic.
- **Integration testing:** Packet Capture → Parser → Database → Flask API → Dashboard.
- **UI testing (Playwright):** dashboard load, packet table, search, protocol filters, navigation, alerts, buttons.
- **Regression testing:** rerun prior automated tests after changes.
- **Performance testing:** packets/sec, response time, CPU/memory usage, packet drops, DB performance (measured only — no invented results).

See [`docs/testing.md`](docs/testing.md) for details.

## 13. Team Members

| Name | Role | Focus Area |
|---|---|---|
| Aradhya Sharma | Backend & Packet Capture | Python, Scapy, packet capture/parsing, TCP/UDP/ICMP handling |
| Chandramolee Mudgal | Frontend | HTML/CSS/JS, Chart.js, dashboard, packet table, filters |
| Naman Pareek | Database | SQLite schema, queries, packet storage and retrieval |
| Neelesh Bansal | Security | Port scan detection, abnormal traffic detection, security alerts |
| Janmejai Mudgal | Testing, Integration & Documentation | Pytest, Playwright, regression testing, Flask integration, GitHub workflow, README and project documentation |

> Replace with actual names once assigned.

## 14. Sprint Plan

See [`docs/sprint-plan.md`](docs/sprint-plan.md) for the full 6-sprint breakdown. Current phase: **Sprint 1 — Project Setup & Basic Capture**.

## 15. Limitations

- Only sees traffic available to the selected capture interface.
- Encrypted application traffic cannot simply be read/decrypted by the analyzer.
- Basic detection rules can produce false positives and false negatives.
- Performance can degrade under very high traffic volumes.
- This is an educational/basic network analyzer, not a replacement for professional tools such as Wireshark.

## 16. Future Scope

Not implemented in the current 6-week timeline:

- IPv6 support
- More protocol analysis
- PCAP import/export
- Better network visualization / network topology visualization
- More security detection rules
- Improved anomaly detection
- Role-based access control
- More advanced traffic analytics
EOF_README_MD
git add README.md
git commit -m "docs: update project readme"
