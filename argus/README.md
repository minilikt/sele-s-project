# ARGUS — Attack Surface Intelligence

Web app that monitors an organization's authorized digital assets: automated asset discovery, security misconfiguration detection, risk scoring, change detection, and a security dashboard.

## Stack

- Frontend: React (Vite) + Chart.js
- Backend: Node.js + Express
- Database: MongoDB
- Asset discovery: Subfinder + DNS-over-HTTPS + HTTP/TLS inspection

## Layout

```
argus/
  frontend/   React app (Vite)
  backend/    Express API
```

## Getting started

```
cd frontend
npm install
npm run dev
```

```
cd backend
npm install
npm run dev
```

Only scan domains and systems you own or have explicit authorization to assess.

## Roadmap

- [ ] Asset discovery (subdomains, DNS record changes)
- [ ] Misconfiguration checks (TLS expiry, security headers)
- [ ] Risk scoring engine
- [ ] Change detection + alerts
- [ ] Security dashboard + reports
