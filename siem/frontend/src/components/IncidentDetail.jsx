import React, { useState, useEffect } from 'react';
import { fetchIncident, updateIncidentStatus, generateReport } from '../api';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';
import IncidentTimeline from './IncidentTimeline';

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

export default function IncidentDetail({ incidentId, onNavigate }) {
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notes, setNotes] = useState('');
  const [reportLoading, setReportLoading] = useState(false);
  const [report, setReport] = useState(null);

  useEffect(() => {
    setLoading(true);
    fetchIncident(incidentId).then(({ data }) => {
      if (data) {
        setIncident(data);
        setNotes(data.notes || '');
      }
      setLoading(false);
    });
  }, [incidentId]);

  const handleStatusChange = async (newStatus) => {
    await updateIncidentStatus(incidentId, newStatus);
    const { data } = await fetchIncident(incidentId);
    if (data) setIncident(data);
  };

  const handleGenerateReport = async () => {
    setReportLoading(true);
    const { data } = await generateReport(incidentId);
    if (data) setReport(data);
    setReportLoading(false);
  };

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;
  if (!incident) return <div className="empty-state">Incident not found.</div>;

  const alerts = incident.alerts || [];
  const techniques = incident.techniques || incident.mitre_techniques || [];
  const timelineEvents = incident.timeline || incident.events || alerts.flatMap(a => a.events || []);

  return (
    <div className="page">
      <button className="btn btn-secondary back-btn" onClick={() => onNavigate('incidents')}>
        ← Back to Incidents
      </button>

      <div className="detail-header">
        <h1 className="page-title">{incident.title || `Incident #${incident.id}`}</h1>
        <div className="detail-meta">
          <SeverityBadge severity={incident.severity} />
          <select
            className="inline-select"
            value={incident.status || 'open'}
            onChange={(e) => handleStatusChange(e.target.value)}
          >
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
          </select>
          <span className="detail-time">{formatTime(incident.created_at)}</span>
        </div>
      </div>

      {/* Description */}
      {incident.description && (
        <div className="card">
          <h2 className="card-title">Description</h2>
          <p className="card-text">{incident.description}</p>
        </div>
      )}

      {/* MITRE Techniques */}
      {techniques.length > 0 && (
        <div className="card">
          <h2 className="card-title">MITRE ATT&CK Techniques</h2>
          <div className="technique-tags">
            {techniques.map((t, i) => (
              <span key={i} className="technique-tag">
                {typeof t === 'string' ? t : `${t.id || t.technique_id} — ${t.name || ''}`}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Linked Alerts */}
      {alerts.length > 0 && (
        <div className="card">
          <h2 className="card-title">Linked Alerts ({alerts.length})</h2>
          <div className="alert-cards">
            {alerts.map((a, i) => (
              <div
                key={i}
                className="alert-mini-card clickable-row"
                onClick={() => onNavigate('alert-detail', a.id)}
              >
                <div className="alert-mini-header">
                  <span>{a.rule_name || a.title || `Alert #${a.id}`}</span>
                  <SeverityBadge severity={a.severity} />
                </div>
                <div className="alert-mini-meta">
                  <StatusBadge status={a.status} />
                  <span>{formatTime(a.created_at || a.timestamp)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Timeline */}
      {timelineEvents.length > 0 && (
        <div className="card">
          <h2 className="card-title">Timeline</h2>
          <IncidentTimeline events={timelineEvents} />
        </div>
      )}

      {/* Investigation Notes */}
      <div className="card">
        <h2 className="card-title">Investigation Notes</h2>
        <textarea
          className="notes-textarea"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Add investigation notes here..."
          rows={5}
        />
      </div>

      {/* Actions */}
      <div className="card action-bar">
        <button className="btn btn-primary" onClick={handleGenerateReport} disabled={reportLoading}>
          {reportLoading ? 'Generating...' : '📄 Generate Report'}
        </button>
        <button
          className="btn btn-primary"
          onClick={() => onNavigate('ai', { contextType: 'incident', contextId: incidentId })}
        >
          🤖 Ask AI
        </button>
      </div>

      {/* Generated Report */}
      {report && (
        <div className="card">
          <h2 className="card-title">Generated Report</h2>
          <pre className="report-block">{typeof report === 'string' ? report : JSON.stringify(report, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
