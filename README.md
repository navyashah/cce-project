# Continuous Compliance Engine

A lightweight internal web application that models **SOC 2 controls as code**, continuously evaluates system configuration state, stores **audit-ready evidence**, and exposes real-time compliance health through a simple dashboard and API.

This project mirrors how modern security and GRC teams automate compliance monitoring, while remaining deterministic and demo-friendly.

---

## What This Project Does

The Continuous Compliance Engine implements an end-to-end compliance evaluation pipeline:

- **Controls as Code**  
  SOC 2 controls are defined in YAML, including risk, expected system state, severity, check frequency, and evidence sources.

- **Evidence Collection (Mocked)**  
  The system collects timestamped evidence snapshots representing system configurations (e.g. IAM, CI/CD, logging).  
  Collectors are mocked for demo purposes but mirror real infrastructure and SaaS APIs.

- **Evaluation Engine**  
  Each control is evaluated by comparing expected state against collected evidence.  
  Results are stored as immutable, point-in-time evaluations (PASS / FAIL) with remediation guidance.

- **Audit-Ready Storage**  
  Evidence and evaluations are append-only and fully traceable over time.

- **Dashboard & API**  
  The application exposes both a human-readable internal UI and JSON APIs for reporting and automation.

---

## Controls Implemented

- **CC6.1 — Logical Access Controls**  
  Identity, MFA enforcement, and privileged access restrictions

- **CC7.2 — Logging and Monitoring**  
  Centralized logging and log retention requirements

- **CC8.1 — Change Management**  
  Code review and production deployment approvals

---

## Demo Mode (Drift Simulation)

The engine supports a demo mode that simulates compliance drift.

When enabled, mocked evidence violates expected control state, causing controls to fail and alerts to be generated for high-severity issues.

---

## Running Locally

### Prerequisites
- Python 3.10+
- PostgreSQL running locally

### Setup

```bash
git clone https://github.com/<your-username>/continuous-compliance-engine.git
cd continuous-compliance-engine

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Environment Variables

Create a .env file in the project root:

DATABASE_URL=postgresql+psycopg2://<user>:<password>@localhost:5432/<db_name>
SIMULATE_DRIFT=0


To demo failures, set SIMULATE_DRIFT=1.

Run
python3 -m uvicorn api.server:app --reload

## Access
- UI: http://127.0.0.1:8000/ui/controls
- API Docs: http://127.0.0.1:8000/docs

Click Run Checks in the UI to evaluate all controls.

## Architecture
- Backend: FastAPI
- Database: PostgreSQL
- ORM: SQLAlchemy
- UI: Server-rendered HTML (Jinja2)
