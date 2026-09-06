# Requirements

## 1. Purpose

This document defines the functional and non-functional requirements for the Network Traffic Analyzer, a student project built over 6 one-week Agile sprints. It is scoped to be achievable in that timeframe — see [Out of Scope](#5-out-of-scope) below.

## 2. Functional Requirements

### 2.1 Packet Capture
- FR-1: The system shall capture live network packets from a user-selected, authorized network interface using Scapy.
- FR-2: The system shall support capture of TCP, UDP, and ICMP protocols initially.

### 2.2 Packet Parsing & Metadata Extraction
- FR-3: The system shall extract, per packet: packet ID, timestamp, source IP, destination IP, source port, destination port, protocol, packet size, and TCP flags (where applicable).
- FR-4: The system shall not store full packet payloads by default (metadata only).

### 2.3 Storage
- FR-5: The system shall persist packet metadata to a SQLite `packets` table.
- FR-6: The system shall persist generated alerts to a SQLite `security_alerts` table.
- FR-7: All database writes shall use parameterized queries to prevent SQL injection.

### 2.4 Dashboard
- FR-8: The system shall provide a web dashboard displaying a packet table (source IP, destination IP, ports, protocol, timestamp, packet size).
- FR-9: The dashboard shall display total packet count and TCP/UDP/ICMP breakdown statistics.
- FR-10: The dashboard shall provide traffic charts using Chart.js.
- FR-11: The dashboard shall display security alerts.

### 2.5 Filtering & Search
- FR-12: Users shall be able to filter traffic by protocol (TCP/UDP/ICMP).
- FR-13: Users shall be able to search/filter by source or destination IP.
- FR-14: Users shall be able to filter by port.

### 2.6 Security Detection
- FR-15: The system shall detect a "Possible Port Scan" when a single source IP contacts an unusually large number of distinct ports within a configurable time window.
- FR-16: The system shall detect "Abnormal Traffic" when traffic rate exceeds a configurable threshold.
- FR-17: Alerts shall use non-definitive wording (e.g. "Possible", "Suspicious", "Abnormal") — the system shall never claim a confirmed attack.
- FR-18: Detection thresholds shall be configurable, not hard-coded constants.

### 2.7 Testing
- FR-19: Core packet parsing, extraction, database, and detection logic shall have automated unit tests (Pytest).
- FR-20: Core module-to-module flows shall have integration tests.
- FR-21: The dashboard shall have automated UI tests (Playwright) covering load, table display, search, filters, navigation, and alerts.

## 3. Non-Functional Requirements

- NFR-1 (Security): No hard-coded credentials or secrets; use `.env` for configuration, and never commit `.env` to Git.
- NFR-2 (Security): All user input shall be validated before use.
- NFR-3 (Data Minimization): Only necessary packet metadata is stored; unnecessary sensitive data is not exposed.
- NFR-4 (Simplicity): The implementation shall stay within the agreed technology stack and avoid unnecessary complexity (see [Out of Scope](#5-out-of-scope)).
- NFR-5 (Usability): The dashboard UI shall be simple and understandable, appropriate for a student project rather than a commercial product.
- NFR-6 (Honesty): Performance results shall only be documented after being actually measured — no invented figures.
- NFR-7 (Modularity): The architecture shall be modular enough for team members to work independently on capture, database/security, frontend, and testing concurrently.

## 4. Technology Constraints

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

No alternative frameworks or libraries should be introduced without team agreement.

## 5. Out of Scope

The following are explicitly **not** to be implemented unless later agreed upon by the whole team, and may only be mentioned under Future Scope:

- Machine learning / deep learning
- SDN
- Blockchain
- Complex IDS/IPS systems
- Distributed systems
- Kubernetes
- Microservices
- Cloud infrastructure
- Advanced packet payload inspection

## 6. Known Limitations (Accepted by Design)

- Visibility is limited to traffic on the selected capture interface.
- Encrypted application traffic cannot be decrypted/read by the analyzer.
- Rule-based detection can produce false positives and false negatives.
- Performance may degrade under very high traffic volumes.
- This tool is educational and is not a replacement for Wireshark or other professional tools.
