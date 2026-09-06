# Network Traffic Analyzer

A web-based Computer Networks project inspired by the basic functionality of Wireshark. It captures network packets from an authorized network interface, extracts useful metadata, stores it, displays it through a web dashboard, and provides basic traffic analysis and security alerts.

> This project is **not** intended to replace Wireshark. It is an educational, student-built network monitoring and analysis tool with basic security detection.

**Status:** Sprint 1 of 6 — Project Setup & Basic Capture (in progress)

---

## Project Overview

The Network Traffic Analyzer captures live network packets on an authorized interface, parses them into structured metadata, stores that metadata in a database, and presents it through a browser-based dashboard. Users can filter and search captured traffic, view basic statistics and charts, and see alerts for simple suspicious patterns such as possible port scans or abnormal traffic volume.

**Main flow:**

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
git clone https://github.com/jj-mudgal/network-traffic-analyzer.git
cd network-traffic-analyzer

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

> _Confirm and update these steps once verified end-to-end by the team. Note any OS-specific permission requirements for packet capture (e.g. admin/root privileges or interface selection)._

## Documentation Roadmap

This README grows sprint by sprint. Sections below are **not yet written** — do not add them early, and do not invent content ahead of implementation.

| Section | Added in |
|---|---|
| Features | Sprints 2–4 |
| Database Structure | Sprints 2–4 |
| API Endpoints | Sprints 2–4 |
| Security Features | Sprints 2–4 |
| Testing Approach | Sprint 5 |
| Testing Results | Sprint 5 |
| Screenshots | Sprint 6 |
| Limitations & Future Scope | Sprint 6 |
| Final README polish | Sprint 6 |
| Final Report | Sprint 6 |

## Team Members

| Name | Role |
|---|---|
| Aradhya Sharma | Backend & Packet Capture |
| Chandramolee | Frontend |
| Naman | Database |
| Neelesh | Security |
| Janmejai | Testing & Integration |

For contributor/AI-assistant context (architecture decisions, module ownership, Git workflow, conventions), see [`context.md`](./context.md).