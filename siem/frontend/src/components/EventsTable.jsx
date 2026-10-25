import React, { useState, useEffect } from 'react';
import { fetchEvents } from '../api';
import SeverityBadge from './SeverityBadge';
import ExportButtons from './ExportButtons';

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

export default function EventsTable() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [filters, setFilters] = useState({ event_type: '', severity: '', account: '' });
  const [expandedRow, setExpandedRow] = useState(null);
  const pageSize = 50;

  const load = () => {
    setLoading(true);
    fetchEvents({
      skip: page * pageSize,
      limit: pageSize,
      ...filters,
    }).then(({ data }) => {
      if (data) {
        const list = Array.isArray(data) ? data : data.events || [];
        setEvents(list);
        setTotal(data.total ?? list.length);
      }
      setLoading(false);
    });
  };

  useEffect(() => { load(); }, [page, filters]);

  const handleFilter = (key, value) => {
    setPage(0);
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const start = page * pageSize + 1;
  const end = Math.min(start + events.length - 1, total);

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Security Events</h1>
        <ExportButtons scope="events" />
      </div>

      {/* Filters */}
      <div className="filter-bar">
        <select
          value={filters.event_type}
          onChange={(e) => handleFilter('event_type', e.target.value)}
          className="filter-select"
        >
          <option value="">All Event Types</option>
          <option value="Authentication">Authentication</option>
          <option value="Process">Process</option>
          <option value="Network">Network</option>
          <option value="File">File</option>
          <option value="Registry">Registry</option>
          <option value="PowerShell">PowerShell</option>
        </select>
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
          <option value="info">Info</option>
        </select>
        <input
          type="text"
          placeholder="Search by account..."
          value={filters.account}
          onChange={(e) => handleFilter('account', e.target.value)}
          className="filter-input"
        />
      </div>

      {loading ? (
        <div className="loading-spinner"><div className="spinner" /></div>
      ) : events.length === 0 ? (
        <div className="empty-state">No events found matching your filters.</div>
      ) : (
        <>
          <div className="card">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event ID</th>
                  <th>Type</th>
                  <th>Account</th>
                  <th>Source IP</th>
                  <th>Computer</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {events.map((evt, idx) => (
                  <React.Fragment key={evt.id || idx}>
                    <tr
                      className="clickable-row"
                      onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                    >
                      <td>{formatTime(evt.timestamp)}</td>
                      <td className="mono">{evt.event_id || '—'}</td>
                      <td>{evt.event_type || '—'}</td>
                      <td>{evt.account || '—'}</td>
                      <td className="mono">{evt.source_ip || '—'}</td>
                      <td>{evt.computer || '—'}</td>
                      <td><SeverityBadge severity={evt.severity} /></td>
                    </tr>
                    {expandedRow === idx && (
                      <tr className="expanded-row">
                        <td colSpan={7}>
                          <pre className="json-block">{JSON.stringify(evt, null, 2)}</pre>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="pagination">
            <button
              className="btn btn-secondary"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
            >
              ← Previous
            </button>
            <span className="pagination-info">
              {start}–{end} of {total}
            </span>
            <button
              className="btn btn-secondary"
              onClick={() => setPage((p) => p + 1)}
              disabled={end >= total}
            >
              Next →
            </button>
          </div>
        </>
      )}
    </div>
  );
}
