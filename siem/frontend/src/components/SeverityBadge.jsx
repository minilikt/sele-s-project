import React from 'react';

const SEVERITY_MAP = {
  critical: { label: 'CRITICAL', className: 'severity-critical' },
  high: { label: 'HIGH', className: 'severity-high' },
  medium: { label: 'MEDIUM', className: 'severity-medium' },
  low: { label: 'LOW', className: 'severity-low' },
  info: { label: 'INFO', className: 'severity-info' },
  informational: { label: 'INFO', className: 'severity-info' },
};

export default function SeverityBadge({ severity }) {
  const key = (severity || 'info').toLowerCase();
  const cfg = SEVERITY_MAP[key] || SEVERITY_MAP.info;
  return <span className={`badge ${cfg.className}`}>{cfg.label}</span>;
}
