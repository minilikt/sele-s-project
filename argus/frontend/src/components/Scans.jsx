import React, { useState, useEffect } from 'react';
import { runScan, fetchScanHistory } from '../api';
import StatusBadge from './StatusBadge';
import ExportButtons from './ExportButtons';

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

export default function Scans() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [domain, setDomain] = useState('acme-lab.local');
  const [result, setResult] = useState(null);

  const load = () => {
    setLoading(true);
    fetchScanHistory().then(({ data }) => {
      if (data) setHistory(Array.isArray(data) ? data : data.scans || []);
      setLoading(false);
    });
  };

  useEffect(() => { load(); }, []);

  const handleScan = async () => {
    setScanning(true);
    setResult(null);
    const { data, error } = await runScan(domain);
    setResult(data || { error });
    setScanning(false);
    load();
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Scans</h1>
        <ExportButtons scope="report" />
      </div>

      <div className="card">
        <h2 className="card-title">Run a Scan</h2>
        <p className="card-text">
          Scans the target domain for subdomains, checks web services, TLS
          certificates and security headers, then scores the findings. The
          default lab domain is safe and self-contained — only scan domains you
          own or are authorised to assess.
        </p>
        <div className="scan-form">
          <input
            type="text"
            className="filter-input"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="target domain"
          />
          <button className="btn btn-primary" onClick={handleScan} disabled={scanning || !domain.trim()}>
            {scanning ? '⏳ Scanning...' : '🔎 Start Scan'}
          </button>
        </div>
        {result && (
          <div className="result-card">
            {result.error ? (
              <p className="card-text" style={{ color: 'var(--accent-red)' }}>Error: {result.error}</p>
            ) : (
              <p className="card-text">
                Scan #{result.id} complete: {result.assets_discovered} assets,
                {result.new_assets} new, {result.new_findings} new findings.
              </p>
            )}
          </div>
        )}
      </div>

      <div className="card">
        <h2 className="card-title">Scan History</h2>
        {loading ? (
          <div className="loading-spinner"><div className="spinner" /></div>
        ) : history.length === 0 ? (
          <div className="empty-state">No scans yet.</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Started</th>
                <th>Domain</th>
                <th>Assets</th>
                <th>New</th>
                <th>Findings</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {history.map((s) => (
                <tr key={s.id}>
                  <td>{formatTime(s.started_at)}</td>
                  <td className="mono">{s.domain}</td>
                  <td>{s.assets_discovered}</td>
                  <td>{s.new_assets}</td>
                  <td>{s.new_findings}</td>
                  <td><StatusBadge status={s.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
