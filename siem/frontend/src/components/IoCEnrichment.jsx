import React, { useState } from 'react';
import { lookupIoC, scanIoC } from '../api';

const TYPES = ['auto', 'hash', 'ip', 'domain'];

function verdictClass(v) {
  if (v === 'malicious') return 'rep-malicious';
  if (v === 'suspicious') return 'rep-suspicious';
  return 'rep-clean';
}

export default function IoCEnrichment() {
  const [value, setValue] = useState('');
  const [type, setType] = useState('auto');
  const [result, setResult] = useState(null);
  const [lookupLoading, setLookupLoading] = useState(false);

  const [scanResult, setScanResult] = useState(null);
  const [scanLoading, setScanLoading] = useState(false);

  const handleLookup = async () => {
    if (!value.trim()) return;
    setLookupLoading(true);
    setResult(null);
    const { data, error } = await lookupIoC(value, type === 'auto' ? undefined : type);
    setResult(data || { error });
    setLookupLoading(false);
  };

  const handleScan = async () => {
    setScanLoading(true);
    setScanResult(null);
    const { data, error } = await scanIoC();
    setScanResult(data || { error });
    setScanLoading(false);
  };

  return (
    <div className="page">
      <h1 className="page-title">IoC Enrichment</h1>
      <p className="card-text">
        Check observables (hashes, IPs, domains) against the built-in threat
        intelligence feed and scan alerts for indicators. This first version is
        fully local and deterministic.
      </p>

      <div className="card">
        <h2 className="card-title">Lookup Observable</h2>
        <div className="ioc-input-row">
          <input
            type="text"
            className="filter-input" style={{ flex: 1 }}
            placeholder="Enter an IP, file hash (MD5/SHA1/SHA256) or domain..."
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
          <select className="filter-select" value={type} onChange={(e) => setType(e.target.value)}>
            {TYPES.map((t) => (
              <option key={t} value={t}>{t.toUpperCase()}</option>
            ))}
          </select>
          <button className="btn btn-primary" onClick={handleLookup} disabled={lookupLoading || !value.trim()}>
            {lookupLoading ? 'Checking...' : 'Check'}
          </button>
        </div>
        {result && (
          <div className="result-card">
            {result.error ? (
              <p className="card-text" style={{ color: 'var(--red)' }}>{result.error}</p>
            ) : (
              <div className="ioc-result">
                <div className="detail-header" style={{ display: 'flex', gap: 8, alignItems: 'center', gap: 10 }}>
                  <span className={`ioc-rep-badge ${verdictClass(result.verdict)}`}>{String(result.verdict).toUpperCase()}</span>
                  <span className="mono">{result.value}</span>
                  <span className="text-muted">{result.type}</span>
                  <span className="text-muted">{result.name}</span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="card">
        <h2 className="card-title">Scan Alerts for Indicators</h2>
        <button className="btn btn-primary" onClick={handleScan} disabled={scanLoading}>
          {scanLoading ? 'Scanning alerts...' : '🧬 Scan Alerts for IoCs'}
        </button>
        {scanResult && (
          <div className="result-card">
            <pre className="json-block">{JSON.stringify(scanResult, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
