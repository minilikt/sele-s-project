import { clearSession, getToken } from './session';

const API_BASE = import.meta.env.VITE_API_BASE || '/api';

function authHeaders(extra = {}) {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}`, ...extra } : { ...extra };
}

function handleUnauthorised() {
  if (getToken()) {
    clearSession();
    window.dispatchEvent(new Event('argus:logout'));
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
      const body = await res.text();
      let detail = body;
      try {
        detail = JSON.parse(body).detail ?? body;
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

// Scans
export const runScan = (domain) =>
  request('/scan', { method: 'POST', body: JSON.stringify({ domain }) });
export const fetchScanHistory = (limit = 50) => request(`/scan/history${qs({ limit })}`);
export const fetchLatestScan = () => request('/scan/latest');

// Assets
export const fetchAssets = (params) => request(`/assets${qs(params)}`);
export const fetchAsset = (id) => request(`/assets/${id}`);

// Findings
export const fetchFindings = (params) => request(`/findings${qs(params)}`);
export const fetchFindingStats = () => request('/findings/stats');
export const fetchFindingMetrics = () => request('/findings/metrics');
export const updateFindingStatus = (id, status, extra = {}) =>
  request(`/findings/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status, ...extra }),
  });

// AI
export const askAI = (question) =>
  request('/ai/ask', { method: 'POST', body: JSON.stringify({ question }) });
export const generateReport = () => request('/ai/report', { method: 'POST' });

// Dashboard
export const fetchDashboardStats = () => request('/dashboard/stats');

// Export
export const exportFindingsJSON = () => request('/export/findings.json');
export const exportAssetsJSON = () => request('/export/assets.json');
export const exportReportTxt = () => request('/export/report.txt');

// Health
export const fetchHealth = () =>
  fetch(`${API_BASE}/health`)
    .then((r) => r.json())
    .then((data) => ({ data, error: null }))
    .catch((err) => ({ data: null, error: err.message }));
