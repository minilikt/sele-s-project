import React, { useState, useEffect } from 'react';
import { fetchIncidents } from '../api';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';
import ExportButtons from './ExportButtons';

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

export default function IncidentsList({ onNavigate }) {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');

  useEffect(() => {
    setLoading(true);
    fetchIncidents().then(({ data }) => {
      if (data) setIncidents(Array.isArray(data) ? data : data.incidents || []);
      setLoading(false);
    });
  }, []);

  const filtered = incidents.filter((inc) => {
    if (filterStatus && (inc.status || '').toLowerCase() !== filterStatus) return false;
    if (filterSeverity && (inc.severity || '').toLowerCase() !== filterSeverity) return false;
    return true;
  });

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Incidents</h1>
        <ExportButtons scope="incidents" />
      </div>

      <div className="filter-bar">
        <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} className="filter-select">
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="contained">Contained</option>
          <option value="resolved">Resolved</option>
        </select>
        <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)} className="filter-select">
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {loading ? (
        <div className="loading-spinner"><div className="spinner" /></div>
      ) : filtered.length === 0 ? (
        <div className="empty-state">No incidents found. Run correlation to discover incidents.</div>
      ) : (
        <div className="incidents-grid">
          {filtered.map((inc) => (
            <div
              key={inc.id}
              className="incident-card card clickable-row"
              onClick={() => onNavigate('incident-detail', inc.id)}
            >
              <div className="incident-card-header">
                <h3 className="incident-card-title">{inc.title || `Incident #${inc.id}`}</h3>
                <SeverityBadge severity={inc.severity} />
              </div>
              <p className="incident-card-desc">
                {inc.description || 'No description available.'}
              </p>
              <div className="incident-card-meta">
                <StatusBadge status={inc.status} />
                <span className="incident-alert-count">
                  {(inc.alert_ids || inc.alerts || []).length} alert(s)
                </span>
                <span className="incident-time">{formatTime(inc.created_at)}</span>
              </div>
              {(inc.techniques || inc.mitre_techniques || []).length > 0 && (
                <div className="incident-techniques">
                  {(inc.techniques || inc.mitre_techniques || []).map((t, i) => (
                    <span key={i} className="technique-tag">
                      {typeof t === 'string' ? t : t.id || t.technique_id}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
