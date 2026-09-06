# Sprint Plan

6 one-week Agile sprints.

## Sprint 1 — Project Setup & Basic Capture *(current)*

- Repo / project setup
- README
- Project structure
- `requirements.txt`
- `.gitignore`
- Scapy setup
- Basic packet capture
- Extract source/destination IP
- Extract timestamp
- SQLite setup, `packets` table
- Flask setup, initial dashboard
- Pytest setup, initial unit tests

**Sprint 1 Issues:**
1. Implement Basic Packet Capture and Metadata Extraction
2. Set up SQLite database and create packets table
3. Set Up Pytest and Initial Unit Tests
4. Set Up Flask Backend and API
5. Create Initial Dashboard and Packet Display
6. Create Project Documentation

## Sprint 2 — Packet Analysis & Storage

- TCP/UDP/ICMP parsing
- Port extraction
- Packet size extraction
- Database storage
- Packet retrieval API
- Display packet metadata
- Parser tests
- Database tests

## Sprint 3 — Filters & Statistics

- TCP/UDP/ICMP filtering
- IP search
- Port search
- TCP flag extraction
- Traffic statistics
- Charts
- API integration
- Playwright dashboard tests

## Sprint 4 — Security & Alerts

- Possible port scan detection
- Abnormal traffic detection
- Security alerts
- Alert history
- Security tests
- Playwright security tests
- Integrate alerts into dashboard

## Sprint 5 — Testing & Optimization

- Unit/integration/Playwright/regression testing
- Performance testing
- Packet-processing optimization
- Database optimization
- UI improvements
- Bug fixing

## Sprint 6 — Finalization

- Final bug fixing
- Final regression/Playwright/performance testing
- README completion
- Technical documentation
- Screenshots
- Limitations
- Future scope
- Final report
- Demo prep
- Viva prep

---

## GitHub Project Management

**Repository:** `network-traffic-analyzer`
**GitHub Project:** `network traffic analyzer - development`

### Kanban Statuses

| Status | Meaning |
|---|---|
| Backlog | Future/unplanned work |
| Todo | Work selected for the current sprint |
| In Progress | Currently being developed |
| Testing | Development complete, QA/testing in progress |
| Done | Implemented, reviewed, and tested |

### Recommended Fields

- **Sprint:** Sprint 1–6
- **Priority:** High / Medium / Low
- **Labels/modules:** backend, frontend, database, security, testing, integration, documentation

## Git Workflow

```
Issue → Feature branch → Implementation → Commit → Pull Request
  → Code review → Testing → Merge to main → Done
```

Do not push experimental work directly to `main`.

**Suggested branch names:**
- `feature/packet-capture`
- `feature/dashboard`
- `feature/database-security`
- `feature/testing`
- `feature/integration`

### Commit Convention

Format: `type: short description`

Examples: `feat: implement basic packet capture`, `feat: add tcp packet parsing`, `test: add packet parser tests`, `fix: handle malformed packets`, `perf: optimize database queries`, `docs: update project readme`, `chore: configure development environment`.

Avoid vague commits ("changes", "updated", "final", "done", "stuff") and don't create artificial commits just to inflate commit count.
