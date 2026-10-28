import { clearSession, getToken } from './session';

const API_BASE = import.meta.env.VITE_API_BASE || '/api';

function authHeaders(extra = {}) {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}`, ...extra } : { ...extra };
}

function handleUnauthorised() {
  if (getToken()) {
    clearSession();
    window.dispatchEvent(new Event('sentinel:logout'));
  }
}

async function request(endpoint, options = {}) {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...authHeaders(options.headers) },
    });
    if (res.status === 401) {
      handleUnauthorised();
    }
    if (!res.ok) {
      const errorBody = await res.text();
      let detail = errorBody;
      try {
        detail = JSON.parse(errorBody).detail ?? errorBody;
      } catch {
        // not JSON; keep the raw body
      }
      return {
        data: null,
        error: `HTTP ${res.status}: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`,
      };
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

// Authentication
export const login = (username, password) =>
  request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
export const fetchMe = () => request('/auth/me');
export const fetchUsers = () => request('/auth/users');
export const createUser = (payload) =>
  request('/auth/users', { method: 'POST', body: JSON.stringify(payload) });
export const updateUser = (id, payload) =>
  request(`/auth/users/${id}`, { method: 'PATCH', body: JSON.stringify(payload) });

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

// Sigma rules are stored as YAML; the list endpoint does not inline it.
export const fetchRuleYaml = async (id) => {
  try {
    const res = await fetch(`${API_BASE}/detection/rules/${id}/yaml`);
    if (!res.ok) return { data: null, error: `HTTP ${res.status}` };
    return { data: await res.text(), error: null };
  } catch (err) {
    return { data: null, error: err.message };
  }
};

export const reloadRules = () => request('/detection/reload', { method: 'POST' });

// Incidents
export const fetchIncidents = () => request('/incidents');
export const fetchIncident = (id) => request(`/incidents/${id}`);
export const updateIncidentStatus = (id, status) =>
  request(`/incidents/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
export const runCorrelation = ({ windowMinutes = 60, rebuild = false } = {}) =>
  request(`/incidents/correlate?window_minutes=${windowMinutes}&rebuild=${rebuild}`, {
    method: 'POST',
  });

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

// Windows log import (.evtx, XML export or JSON)
export const importEventLog = async (file, { skipDuplicates = true, dryRun = false } = {}) => {
  try {
    const form = new FormData();
    form.append('file', file);
    const query = `?skip_duplicates=${skipDuplicates}&dry_run=${dryRun}`;
    // Do not set Content-Type: the browser must add the multipart boundary.
    const res = await fetch(`${API_BASE}/events/import${query}`, {
      method: 'POST',
      body: form,
      headers: authHeaders(),
    });
    if (res.status === 401) {
      handleUnauthorised();
    }
    const payload = await res.json().catch(() => null);
    if (!res.ok) {
      const detail = payload?.detail;
      return {
        data: null,
        error: typeof detail === 'string' ? detail : JSON.stringify(detail || `HTTP ${res.status}`),
      };
    }
    return { data: payload, error: null };
  } catch (err) {
    return { data: null, error: err.message };
  }
};

// Entity graph
export const fetchEntities = (limit = 25) => request(`/entities?limit=${limit}`);
