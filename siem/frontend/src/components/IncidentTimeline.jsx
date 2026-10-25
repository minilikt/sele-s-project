import React from 'react';

export default function IncidentTimeline({ events }) {
  if (!events || events.length === 0) {
    return <div className="empty-state">No timeline events available</div>;
  }

  const sorted = [...events].sort(
    (a, b) => new Date(a.timestamp || a.time) - new Date(b.timestamp || b.time)
  );

  const severityClass = (sev) => {
    const s = (sev || 'info').toLowerCase();
    return `timeline-dot-${s}`;
  };

  const formatTime = (ts) => {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleString();
  };

  return (
    <div className="incident-timeline">
      {sorted.map((evt, idx) => (
        <div className="timeline-entry" key={idx}>
          <div className="timeline-time">{formatTime(evt.timestamp || evt.time)}</div>
          <div className="timeline-connector">
            <span className={`timeline-dot ${severityClass(evt.severity)}`} />
            {idx < sorted.length - 1 && <span className="timeline-line" />}
          </div>
          <div className="timeline-content">
            <div className="timeline-title">
              {evt.description || evt.event_type || evt.rule_name || 'Event'}
            </div>
            {evt.event_type && (
              <span className="badge severity-info">{evt.event_type}</span>
            )}
            {evt.account && (
              <span className="timeline-meta">Account: {evt.account}</span>
            )}
            {evt.source_ip && (
              <span className="timeline-meta">Source: {evt.source_ip}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
