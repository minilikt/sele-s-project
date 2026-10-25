const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000/api';

async function request(endpoint, options = {}) {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      headers: { 'Content-Type': 'application/json', ...options.headers },
      ...options,
    });
    if (!res.ok) {
      const errorBody = await res.text();
      return { data: null, error: `HTTP ${res.status}: ${errorBody}` };
    }
    const data = await res.json();
    return { data, error: null };
  } catch (err) {
    return { data: null, error: err.message };
  }
}

function qs(params) {
  const search = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') search.append(k, v);
  });
  const s = search.toString();
  return s ? `?${s}` : '';
}

// Events
export const fetchEvents = (params) => request(`/events${qs(params)}`);
export const fetchEvent = (id) => request(`/events/${id}`);
export const fetchEventStats = () => request('/events/stats');
export const ingestEvents = (events) =>
  request('/events/ingest', { method: 'POST', body: JSON.stringify(events) });
export const generateSampleLogs = () =>
  request('/events/generate-sample', { method: 'POST' });

// Alerts
export const fetchAlerts = (params) => request(`/alerts${qs(params)}`);
export const fetchAlert = (id) => request(`/alerts/${id}`);
export const updateAlertStatus = (id, status) =>
  request(`/alerts/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
export const fetchAlertStats = () => request('/alerts/stats');

// Detection
export const runDetection = () =>
  request('/detection/run', { method: 'POST' });
export const fetchDetectionRules = () => request('/detection/rules');
export const updateRule = (id, data) =>
  request(`/detection/rules/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  });

// Incidents
export const fetchIncidents = () => request('/incidents');
export const fetchIncident = (id) => request(`/incidents/${id}`);
export const updateIncidentStatus = (id, status) =>
  request(`/incidents/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
export const runCorrelation = () =>
  request('/incidents/correlate', { method: 'POST' });

// MITRE
export const fetchMitreTechniques = () => request('/mitre/techniques');
export const fetchMitreTechnique = (id) => request(`/mitre/techniques/${id}`);
export const fetchMitreCoverage = () => request('/mitre/coverage');

// AI Assistant
export const askAI = (question, contextType, contextId) =>
  request('/ai/ask', {
    method: 'POST',
    body: JSON.stringify({
      question,
      context_type: contextType,
      context_id: contextId,
    }),
  });
export const generateReport = (incidentId) =>
  request('/ai/report', {
    method: 'POST',
    body: JSON.stringify({ incident_id: incidentId }),
  });
export const generateSummary = (type, id) =>
  request('/ai/summary', {
    method: 'POST',
    body: JSON.stringify({ type, id }),
  });

// Dashboard
export const fetchDashboardStats = () => request('/dashboard/stats');

// Export
export const exportEventsCSV = () => request('/export/events.csv');
export const exportEventsJSON = () => request('/export/events.json');
export const exportAlertsJSON = () => request('/export/alerts.json');
export const exportIncidentsJSON = () => request('/export/incidents.json');

// IoC enrichment
export const lookupIoC = (value, type) =>
  request('/ioc/lookup', { method: 'POST', body: JSON.stringify({ value, type: type || undefined }) });
export const enrichAlertIoC = (id) =>
  request(`/ioc/alert/${id}`, { method: 'POST' });
export const scanIoC = () => request('/ioc/scan', { method: 'POST' });

// Health
export const fetchHealth = () =>
  fetch(`${API_BASE}/health`)
    .then((r) => r.json())
    .then((data) => ({ data, error: null }))
    .catch((err) => ({ data: null, error: err.message }));
