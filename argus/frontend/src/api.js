const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:5000/api';

async function request(endpoint, options = {}) {
  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      headers: { 'Content-Type': 'application/json', ...options.headers },
      ...options,
    });
    if (!res.ok) {
      const body = await res.text();
      return { data: null, error: `HTTP ${res.status}: ${body}` };
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

// Scans
export const runScan = (domain) =>
  request('/scan', { method: 'POST', body: JSON.stringify({ domain }) });
export const fetchScanHistory = () => request('/scan/history');

// Assets
export const fetchAssets = (params) => request(`/assets${qs(params)}`);
export const fetchAsset = (id) => request(`/assets/${id}`);

// Findings
export const fetchFindings = (params) => request(`/findings${qs(params)}`);
export const updateFindingStatus = (id, status) =>
  request(`/findings/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) });

// AI
export const askAI = (question) =>
  request('/ai/ask', { method: 'POST', body: JSON.stringify({ question }) });
export const generateReport = () =>
  request('/ai/report', { method: 'POST' });

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
