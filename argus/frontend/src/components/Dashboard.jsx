import React, { useState, useEffect } from 'react';
import { fetchDashboardStats, fetchAssets, runScan } from '../api';
import StatusBadge from './StatusBadge';

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

export default function Dashboard({ onNavigate }) {
  const [stats, setStats] = useState(null);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState(null);

  const load = () => {
    Promise.all([fetchDashboardStats(), fetchAssets()]).then(
      ([statsRes, assetsRes]) => {
        if (statsRes.data) setStats(statsRes.data);
        if (assetsRes.data) setAssets(Array.isArray(assetsRes.data) ? assetsRes.data : assetsRes.data.assets || []);
        setLoading(false);
      }
    );
  };

  useEffect(() => { load(); }, []);

  const handleScan = async () => {
    setScanning(true);
    setScanMsg(null);
    const { data, error } = await runScan();
    setScanMsg(data ? `Scan complete — ${data.new_assets} new asset(s), ${data.new_findings} new finding(s).` : `Scan failed: ${error}`);
    setScanning(false);
    load();
  };

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  const sev = stats?.findings_by_severity || {};
  const maxSev = Math.max(1, ...Object.values(sev));
  const sevColors = {
    Critical: 'var(--severity-critical)',
    High: 'var(--severity-high)',
    Medium: 'var(--severity-medium)',
    Low: 'var(--severity-low)',
    Info: 'var(--severity-info)',
  };

  const recentNew = assets.filter((a) => a.is_new).slice(0, 8);

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Attack Surface Dashboard</h1>
        <button className="btn btn-primary" onClick={handleScan} disabled={scanning}>
          {scanning ? 'Scanning...' : 'Run scan'}
        </button>
      </div>

      {scanMsg && <div className="card result-card"><p className="card-text">{scanMsg}</p></div>}

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{stats?.total_assets ?? 0}</div>
          <div className="stat-label">Total Assets</div>
        </div>
        <div className="stat-card stat-card-alert">
          <div className="stat-value">{stats?.new_assets ?? 0}</div>
          <div className="stat-label">Newly Discovered</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats?.risk?.critical ?? 0}</div>
          <div className="stat-label">Critical Findings</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats?.risk?.high ?? 0}</div>
          <div className="stat-label">High Findings</div>
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="card">
          <h2 className="card-title">Domain Risk</h2>
          <div className="risk-gauge">
            <span className="risk-score">{stats?.risk?.domain_risk_score ?? 0}</span>
            <span className="risk-level">/ 100 · {stats?.risk?.risk_level}</span>
          </div>
          <div className="risk-breakdown">
            {['Critical', 'High', 'Medium', 'Low'].map((s) => (
              <div className="severity-bar-row" key={s}>
                <span className="severity-bar-label">{s}</span>
                <div className="severity-bar-track">
                  <div
                    className="severity-bar-fill"
                    style={{ width: `${((sev[s] || 0) / maxSev) * 100}%`, backgroundColor: sevColors[s] }}
                  />
                </div>
                <span className="severity-bar-count">{sev[s] || 0}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h2 className="card-title">Newly Discovered Assets</h2>
          {recentNew.length === 0 ? (
            <div className="empty-state">No new assets. Run a scan to discover changes.</div>
          ) : (
            <table className="data-table compact">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>First Seen</th>
                </tr>
              </thead>
              <tbody>
                {recentNew.map((a) => (
                  <tr key={a.id} className="clickable-row" onClick={() => onNavigate('assets')}>
                    <td className="mono">{a.hostname}</td>
                    <td>{a.asset_type}</td>
                    <td><StatusBadge status={a.status} /></td>
                    <td>{formatTime(a.first_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">Risk Trend Over Scans</h2>
        {(stats?.trend || []).length < 1 ? (
          <div className="empty-state">Run at least one scan to see the risk trend.</div>
        ) : (
          <div className="risk-trend-chart">
            {(stats.trend || []).map((t, i) => (
              <div className="risk-trend-bar" key={i} title={`Risk ${t.risk}`}>
                <span className="text-muted" style={{ fontSize: 11 }}>{t.risk}</span>
                <div
                  className="risk-trend-fill"
                  style={{ height: `${Math.max(4, (t.risk / 100) * 90)}px` }}
                />
                <span className="risk-trend-label">{new Date(t.label).toLocaleDateString()}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <h2 className="card-title">Scan History</h2>
        {(stats?.scan_history || []).length === 0 ? (
          <div className="empty-state">No scans yet. Run a scan to begin monitoring.</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Domain</th>
                <th>Assets</th>
                <th>New</th>
                <th>Findings</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {(stats.scan_history || []).map((s) => (
                <tr key={s.id}>
                  <td>{formatTime(s.started_at)}</td>
                  <td className="mono">{s.domain}</td>
                  <td>{s.assets_discovered}</td>
                  <td>{s.new_assets}</td>
                  <td>{s.new_findings}</td>
                  <td><StatusBadge status={s.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
