import React from 'react';

const STATUS_MAP = {
  open: 'status-open',
  acknowledged: 'status-investigating',
  resolved: 'status-resolved',
  online: 'status-resolved',
  offline: 'status-false-positive',
  unknown: 'status-new',
  running: 'status-investigating',
  complete: 'status-resolved',
  failed: 'status-false-positive',
};

export default function StatusBadge({ status }) {
  const key = (status || 'unknown').toLowerCase();
  const className = STATUS_MAP[key] || 'status-new';
  const label = (status || 'Unknown').replace(/_/g, ' ');
  return (
    <span className={`badge ${className}`}>
      {label.charAt(0).toUpperCase() + label.slice(1)}
    </span>
  );
}
