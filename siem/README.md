# SIEM — Security Information and Event Management

Local security monitoring platform that analyzes Windows event logs and simulated attack scenarios: log analysis, detection rules, event correlation, MITRE ATT&CK mapping, and an AI investigation assistant.

## Stack

- Log ingestion: Python
- Backend API: FastAPI
- Database: PostgreSQL
- Frontend: React (Vite) + Chart.js
- Detection: Sigma-inspired rules
- Framework: MITRE ATT&CK
- AI: Optional LLM integration

## Layout

```
siem/
  frontend/   React app (Vite)
  backend/   FastAPI + detection engine
```

## Getting started

```
cd frontend
npm install
npm run dev
```

```
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

## Roadmap

- [ ] Windows security log analysis
- [ ] Detection rules engine (failed logins, privilege changes, PowerShell)
- [ ] Event correlation + incident timeline
- [ ] MITRE ATT&CK mapping
- [ ] AI investigation assistant
