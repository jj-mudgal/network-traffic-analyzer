# Network Traffic Analyzer

A web-based Computer Networks project inspired by the basic functionality of Wireshark. It captures network packets from an authorized network interface, extracts useful metadata, stores it, displays it through a web dashboard, and provides basic traffic analysis and security alerts.

> This is a student project and is **not** intended to replace Wireshark or any professional packet analysis tool.

**Status:** In development — Sprint 1 of 6

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Objectives](#objectives)
3. [Technology Stack](#technology-stack)
4. [Team Members](#team-members)
5. [Project Structure](#project-structure)
6. [Installation](#installation)
7. [Documentation Roadmap](#documentation-roadmap)

---

## Project Overview

The Network Traffic Analyzer captures live network packets on an authorized interface, parses them into structured metadata, stores that metadata in a database, and presents it through a browser-based dashboard. Users can filter and search captured traffic, view basic statistics and charts, and see alerts for simple suspicious patterns such as possible port scans or abnormal traffic volume.

**Main flow:**

```
Capture → Analyze → Store → Display → Filter/Visualize → Detect Basic Suspicious Activity → Test
```

## Objectives

- Capture network packets in real time
- Extract basic packet information
- Store packet metadata in a database
- Display captured traffic through a web dashboard
- Allow users to filter and search traffic
- Provide basic traffic statistics and visualizations
- Detect simple suspicious traffic patterns
- Generate basic security alerts
- Be tested using automated testing tools
- Be developed using an Agile sprint-based workflow

## Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Packet Capture/Analysis | Scapy |
| Frontend | HTML, CSS, JavaScript |
| Charts | Chart.js |
| Database | SQLite |
| Unit/Integration Testing | Pytest |
| UI Testing | Playwright |
| Version Control | Git, GitHub |
| Project Management | GitHub Projects |

## Team Members

| Name | Role | Focus Area |
|---|---|---|
| Aradhya Sharma | Backend & Packet Capture | Python, Scapy, packet capture/parsing, TCP/UDP/ICMP handling |
| Chandramolee | Frontend | HTML/CSS/JS, Chart.js, dashboard, packet table, filters |
| Naman | Database | SQLite schema, queries, packet storage and retrieval |
| Neelesh | Security | Port scan detection, abnormal traffic detection, security alerts |
| Janmejai Mudgal | Testing, Integration & Documentation | Pytest, Playwright, regression testing, Flask integration, GitHub workflow, README and project documentation |
> _Replace placeholders with real names once assigned._

## Project Structure

> _Update this tree as the real folder layout is created. This is a placeholder shape based on planned modules — do not invent filenames ahead of implementation._

```
network-traffic-analyzer/
├── backend/            # Flask app, API routes
├── capture/            # Scapy packet capture & parsing
├── database/           # SQLite schema, queries
├── security/           # Port scan / abnormal traffic detection
├── frontend/           # HTML, CSS, JS, Chart.js dashboard
├── tests/              # Pytest unit/integration tests, Playwright UI tests
├── docs/               # requirements.md, architecture.md, testing.md, sprint-plan.md
├── requirements.txt
├── .gitignore
├── .env.example
└── README.md
```

## Installation

```bash
git clone https://github.com/jj-mudgal/network-traffic-analyzer.git
cd network-traffic-analyzer
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
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



For contributor/AI-assistant context (architecture decisions, module ownership, Git workflow, conventions), see [`context.md`](./context.md).
