import React, { useState, useEffect } from 'react';
import { fetchAlerts, updateAlertStatus } from '../api';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';
import ExportButtons from './ExportButtons';

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

function confidenceColor(c) {
  if (c >= 80) return 'var(--accent-green)';
  if (c >= 50) return 'var(--accent-yellow)';
  return 'var(--accent-red)';
}

export default function AlertsList({ onNavigate }) {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [filters, setFilters] = useState({ severity: '', status: '' });
  const pageSize = 50;

  const load = () => {
    setLoading(true);
    fetchAlerts({ skip: page * pageSize, limit: pageSize, ...filters }).then(({ data }) => {
      if (data) {
        const list = Array.isArray(data) ? data : data.alerts || [];
        setAlerts(list);
        setTotal(data.total ?? list.length);
      }
      setLoading(false);
    });
  };

  useEffect(() => { load(); }, [page, filters]);

  const handleStatusChange = async (alertId, newStatus, e) => {
    e.stopPropagation();
    await updateAlertStatus(alertId, newStatus);
    load();
  };

  const handleFilter = (key, value) => {
    setPage(0);
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const start = page * pageSize + 1;
  const end = Math.min(start + alerts.length - 1, total);

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Alerts</h1>
        <ExportButtons scope="alerts" />
      </div>

      <div className="filter-bar">
        <select
          value={filters.severity}
          onChange={(e) => handleFilter('severity', e.target.value)}
          className="filter-select"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={filters.status}
          onChange={(e) => handleFilter('status', e.target.value)}
          className="filter-select"
        >
          <option value="">All Statuses</option>
          <option value="new">New</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>

      {loading ? (
        <div className="loading-spinner"><div className="spinner" /></div>
      ) : alerts.length === 0 ? (
        <div className="empty-state">No alerts found. Run the detection engine to generate alerts.</div>
      ) : (
        <>
          <div className="card">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Created</th>
                  <th>Rule Name</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                  <th>Account</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr
                    key={a.id}
                    className="clickable-row"
                    onClick={() => onNavigate('alert-detail', a.id)}
                  >
                    <td>{formatTime(a.created_at || a.timestamp)}</td>
                    <td>{a.rule_name || a.title || '—'}</td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td>
                      <span
                        className="confidence"
                        style={{ color: confidenceColor(a.confidence ?? 0) }}
                      >
                        {a.confidence != null ? `${Math.round(a.confidence)}%` : '—'}
                      </span>
                    </td>
                    <td>{a.account || a.details?.account || '—'}</td>
                    <td><StatusBadge status={a.status} /></td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <select
                        className="inline-select"
                        value={a.status || 'new'}
                        onChange={(e) => handleStatusChange(a.id, e.target.value, e)}
                      >
                        <option value="new">New</option>
                        <option value="investigating">Investigating</option>
                        <option value="resolved">Resolved</option>
                        <option value="false_positive">False Positive</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination">
            <button className="btn btn-secondary" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}>
              ← Previous
            </button>
            <span className="pagination-info">{start}–{end} of {total}</span>
            <button className="btn btn-secondary" onClick={() => setPage((p) => p + 1)} disabled={end >= total}>
              Next →
            </button>
          </div>
        </>
      )}
    </div>
  );
}
