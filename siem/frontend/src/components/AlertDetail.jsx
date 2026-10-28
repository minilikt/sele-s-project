import React, { useState, useEffect } from 'react';
import { fetchAlert, updateAlertStatus, fetchEvent } from '../api';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';
import IncidentTimeline from './IncidentTimeline';

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

export default function AlertDetail({ alertId, onNavigate }) {
  const [alert, setAlert] = useState(null);
  const [relatedEvents, setRelatedEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetchAlert(alertId).then(({ data }) => {
      if (data) {
        setAlert(data);
        // Load related events if IDs are provided
        const eventIds = data.event_ids || data.related_events || [];
        if (eventIds.length > 0) {
          Promise.all(eventIds.map((eid) => fetchEvent(eid))).then((results) => {
            setRelatedEvents(results.filter((r) => r.data).map((r) => r.data));
          });
        }
      }
      setLoading(false);
    });
  }, [alertId]);

  const handleStatusChange = async (newStatus) => {
    await updateAlertStatus(alertId, newStatus);
    const { data } = await fetchAlert(alertId);
    if (data) setAlert(data);
  };

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;
  if (!alert) return <div className="empty-state">Alert not found.</div>;

  const evidence = alert.evidence || alert.details || {};
  const mitreId = alert.mitre_technique_id || alert.mitre_id || '';
  const mitreName = alert.mitre_technique_name || alert.technique_name || '';
  const mitreTactic = alert.mitre_tactic || alert.tactic || '';

  return (
    <div className="page">
      <button className="btn btn-secondary back-btn" onClick={() => onNavigate('alerts')}>
        ← Back to Alerts
      </button>

      <div className="detail-header">
        <h1 className="page-title">{alert.rule_name || alert.title || 'Alert'}</h1>
        <div className="detail-meta">
          <SeverityBadge severity={alert.severity} />
          {alert.confidence != null && (
            <span className="confidence-display">
              Confidence: {Math.round(alert.confidence)}%
            </span>
          )}
          <select
            className="inline-select"
            value={alert.status || 'new'}
            onChange={(e) => handleStatusChange(e.target.value)}
          >
            <option value="new">New</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>
      </div>

      {/* Description */}
      {alert.description && (
        <div className="card">
          <h2 className="card-title">Description</h2>
          <p className="card-text">{alert.description}</p>
        </div>
      )}

      {/* Evidence */}
      <div className="card">
        <h2 className="card-title">Evidence</h2>
        <pre className="json-block">{JSON.stringify(evidence, null, 2)}</pre>
      </div>

      {/* MITRE ATT&CK */}
      {mitreId && (
        <div className="card">
          <h2 className="card-title">MITRE ATT&CK</h2>
          <div className="mitre-info">
            <div className="mitre-tag">
              <strong>{mitreId}</strong> — {mitreName}
            </div>
            {mitreTactic && (
              <div className="mitre-tactic">Tactic: {mitreTactic}</div>
            )}
          </div>
        </div>
      )}

      {/* Related Events */}
      {(alert.event_ids || alert.related_events || []).length > 0 && (
        <div className="card">
          <h2 className="card-title">Related Events</h2>
          <table className="data-table compact">
            <thead>
              <tr>
                <th>Event ID</th>
                <th>Time</th>
                <th>Type</th>
                <th>Account</th>
              </tr>
            </thead>
            <tbody>
              {relatedEvents.map((evt, idx) => (
                <tr key={idx}>
                  <td className="mono">{evt.event_id || evt.id}</td>
                  <td>{formatTime(evt.timestamp)}</td>
                  <td>{evt.event_type || '—'}</td>
                  <td>{evt.account || '—'}</td>
                </tr>
              ))}
              {relatedEvents.length === 0 &&
                (alert.event_ids || alert.related_events || []).map((eid, idx) => (
                  <tr key={idx}>
                    <td className="mono" colSpan={4}>{eid}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Timeline */}
      {relatedEvents.length > 0 && (
        <div className="card">
          <h2 className="card-title">Event Timeline</h2>
          <IncidentTimeline events={relatedEvents} />
        </div>
      )}

      {/* Actions */}
      <div className="card">
        <h2 className="card-title">Investigation</h2>
        <button
          className="btn btn-primary"
          onClick={() => onNavigate('ai', { contextType: 'alert', contextId: alertId })}
        >
          Ask AI about this alert
        </button>
      </div>
    </div>
  );
}
