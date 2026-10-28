import React, { useState, useEffect } from 'react';
import { fetchFindings, updateFindingStatus } from '../api';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';
import ExportButtons from './ExportButtons';
import { hasRole } from '../session';

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

function confidenceColor(c) {
  if (c >= 80) return 'var(--accent-red)';
  if (c >= 50) return 'var(--accent-yellow)';
  return 'var(--accent-green)';
}

export default function Findings() {
  const canWrite = hasRole('analyst');
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ severity: '', category: '', status: '' });
  const [expandedId, setExpandedId] = useState(null);

  const load = () => {
    setLoading(true);
    fetchFindings(filters).then(({ data }) => {
      if (data) setFindings(Array.isArray(data) ? data : data.findings || []);
      setLoading(false);
    });
  };

  useEffect(() => { load(); }, [filters]);

  const handleFilter = (key, value) => setFilters((prev) => ({ ...prev, [key]: value }));

  const handleStatusChange = async (findingId, newStatus, e) => {
    e.stopPropagation();
    await updateFindingStatus(findingId, newStatus);
    load();
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Findings</h1>
        <ExportButtons scope="findings" />
      </div>

      <div className="filter-bar">
        <select className="filter-select" value={filters.severity} onChange={(e) => handleFilter('severity', e.target.value)}>
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select className="filter-select" value={filters.category} onChange={(e) => handleFilter('category', e.target.value)}>
          <option value="">All Categories</option>
          <option value="TLS">TLS</option>
          <option value="Headers">Headers</option>
          <option value="Exposure">Exposure</option>
          <option value="Lifecycle">Lifecycle</option>
        </select>
        <select className="filter-select" value={filters.status} onChange={(e) => handleFilter('status', e.target.value)}>
          <option value="">All Statuses</option>
          <option value="Open">Open</option>
          <option value="Acknowledged">Acknowledged</option>
          <option value="Resolved">Resolved</option>
        </select>
      </div>

      {loading ? (
        <div className="loading-spinner"><div className="spinner" /></div>
      ) : findings.length === 0 ? (
        <div className="empty-state">No findings. Run a scan to assess your assets.</div>
      ) : (
        <div className="card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Risk</th>
                <th>Severity</th>
                <th>Finding</th>
                <th>Asset</th>
                <th>Category</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <React.Fragment key={f.id}>
                  <tr className="clickable-row" onClick={() => setExpandedId(expandedId === f.id ? null : f.id)}>
                    <td className="mono" style={{ fontWeight: 700, color: confidenceColor(f.risk_score) }}>{f.risk_score}</td>
                    <td><SeverityBadge severity={f.severity} /></td>
                    <td>{f.title}{f.stale && <span className="badge stale-badge">stale</span>}</td>
                    <td className="mono">{f.asset_hostname}</td>
                    <td>{f.category}</td>
                    <td><StatusBadge status={f.status} /></td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <select
                        className="inline-select"
                        value={f.status || 'Open'}
                        disabled={!canWrite}
                        title={canWrite ? '' : 'Analyst role required'}
                        onChange={(e) => handleStatusChange(f.id, e.target.value, e)}
                      >
                        <option value="Open">Open</option>
                        <option value="Acknowledged">Acknowledged</option>
                        <option value="Resolved">Resolved</option>
                      </select>
                    </td>
                  </tr>
                  {expandedId === f.id && (
                    <tr className="expanded-row">
                      <td colSpan={7}>
                        <p className="card-text">{f.detail}</p>
                        <p className="text-muted">Recommendation: {f.recommendation}</p>
                        <p className="text-muted">Exposure: {f.exposure} · Confidence: {Math.round((f.confidence || 0) * 100)}% · First seen {formatTime(f.first_seen)}</p>
                        <p className="text-muted">
                          Last seen {formatTime(f.last_seen)} · Observed {f.dedup_count || 1}× · Reopened {f.reopened_count || 0}×
                          {f.assigned_to ? ` · Assigned to ${f.assigned_to}` : ''}
                        </p>
                        {f.resolution_note && (
                          <p className="text-muted">Resolution note: {f.resolution_note}</p>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
