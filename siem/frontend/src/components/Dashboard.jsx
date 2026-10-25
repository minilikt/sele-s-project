import React, { useState, useEffect } from 'react';
import { fetchDashboardStats, fetchAlerts, fetchEvents, fetchMitreCoverage } from '../api';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';

const TACTICS = [
  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Credential Access', 'Discovery', 'Lateral Movement',
];

function formatTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleString();
}

export default function Dashboard({ onNavigate }) {
  const [stats, setStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [recentEvents, setRecentEvents] = useState([]);
  const [coverage, setCoverage] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    Promise.all([
      fetchDashboardStats(),
      fetchAlerts({ skip: 0, limit: 10 }),
      fetchEvents({ skip: 0, limit: 20 }),
      fetchMitreCoverage(),
    ]).then(([statsRes, alertsRes, eventsRes, coverageRes]) => {
      if (statsRes.data) setStats(statsRes.data);
      if (alertsRes.data) setRecentAlerts(Array.isArray(alertsRes.data) ? alertsRes.data : alertsRes.data.alerts || []);
      if (eventsRes.data) setRecentEvents(Array.isArray(eventsRes.data) ? eventsRes.data : eventsRes.data.events || []);
      if (coverageRes.data) setCoverage(coverageRes.data);
      setLoading(false);
    });
  };

  useEffect(() => {
    loadData();
    const id = setInterval(loadData, 30000);
    return () => clearInterval(id);
  }, []);

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  const alertSeverityCounts = {};
  if (stats?.alert_severity_breakdown) {
    Object.assign(alertSeverityCounts, stats.alert_severity_breakdown);
  } else {
    recentAlerts.forEach((a) => {
      const sev = (a.severity || 'info').toLowerCase();
      alertSeverityCounts[sev] = (alertSeverityCounts[sev] || 0) + 1;
    });
  }
  const maxSevCount = Math.max(1, ...Object.values(alertSeverityCounts));

  const sevColors = {
    critical: 'var(--severity-critical)',
    high: 'var(--severity-high)',
    medium: 'var(--severity-medium)',
    low: 'var(--severity-low)',
    info: 'var(--severity-info)',
  };

  return (
    <div className="page dashboard-page">
      <h1 className="page-title">Security Dashboard</h1>

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{stats?.total_events ?? 0}</div>
          <div className="stat-label">Events Ingested</div>
        </div>
        <div className="stat-card stat-card-alert">
          <div className="stat-value">{stats?.active_alerts ?? 0}</div>
          <div className="stat-label">Active Alerts</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats?.open_incidents ?? 0}</div>
          <div className="stat-label">Open Incidents</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">
            {stats?.active_rules ?? 0}
            <span className="stat-sub"> / {stats?.total_rules ?? 0}</span>
          </div>
          <div className="stat-label">Detection Rules Active</div>
        </div>
      </div>

      {/* Two-column layout */}
      <div className="dashboard-grid">
        {/* Alert Severity Breakdown */}
        <div className="card">
          <h2 className="card-title">Alert Severity Breakdown</h2>
          <div className="severity-bars">
            {['critical', 'high', 'medium', 'low'].map((sev) => (
              <div className="severity-bar-row" key={sev}>
                <span className="severity-bar-label">{sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
                <div className="severity-bar-track">
                  <div
                    className="severity-bar-fill"
                    style={{
                      width: `${((alertSeverityCounts[sev] || 0) / maxSevCount) * 100}%`,
                      backgroundColor: sevColors[sev],
                    }}
                  />
                </div>
                <span className="severity-bar-count">{alertSeverityCounts[sev] || 0}</span>
              </div>
            ))}
          </div>
        </div>

        {/* MITRE Coverage */}
        <div className="card">
          <h2 className="card-title">MITRE ATT&CK Coverage</h2>
          <div className="mitre-mini-grid">
            {TACTICS.map((tactic) => {
              const count = coverage?.tactics?.[tactic] ?? coverage?.[tactic] ?? 0;
              return (
                <div className="mitre-mini-cell" key={tactic}>
                  <span className="mitre-mini-name">{tactic}</span>
                  <span className="mitre-mini-count">{count}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="card">
        <h2 className="card-title">Recent Alerts</h2>
        {recentAlerts.length === 0 ? (
          <div className="empty-state">No alerts yet. Generate sample logs to get started.</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>Account</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.map((a) => (
                <tr
                  key={a.id}
                  className="clickable-row"
                  onClick={() => onNavigate('alert-detail', a.id)}
                >
                  <td>{formatTime(a.created_at || a.timestamp)}</td>
                  <td>{a.rule_name || a.title || '—'}</td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td>{a.account || a.details?.account || '—'}</td>
                  <td><StatusBadge status={a.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Recent Events */}
      <div className="card">
        <h2 className="card-title">Recent Events</h2>
        {recentEvents.length === 0 ? (
          <div className="empty-state">No events ingested yet.</div>
        ) : (
          <table className="data-table compact">
            <thead>
              <tr>
                <th>Time</th>
                <th>Event ID</th>
                <th>Type</th>
                <th>Account</th>
                <th>Computer</th>
              </tr>
            </thead>
            <tbody>
              {recentEvents.map((e, idx) => (
                <tr key={e.id || idx}>
                  <td>{formatTime(e.timestamp)}</td>
                  <td className="mono">{e.event_id || e.id || '—'}</td>
                  <td>{e.event_type || '—'}</td>
                  <td>{e.account || '—'}</td>
                  <td>{e.computer || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
