import React from 'react';

const STATUS_MAP = {
  new: 'status-new',
  open: 'status-open',
  investigating: 'status-investigating',
  resolved: 'status-resolved',
  'false positive': 'status-false-positive',
  'false_positive': 'status-false-positive',
  contained: 'status-contained',
  closed: 'status-resolved',
};

export default function StatusBadge({ status }) {
  const key = (status || 'new').toLowerCase();
  const className = STATUS_MAP[key] || 'status-new';
  const label = (status || 'New').replace(/_/g, ' ');
  return (
    <span className={`badge ${className}`}>
      {label.charAt(0).toUpperCase() + label.slice(1)}
    </span>
  );
}
