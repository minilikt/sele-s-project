import React, { useState, useEffect } from 'react';
import { fetchAssets, fetchAsset } from '../api';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

export default function Assets() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ asset_type: '', status: '', is_new: '' });
  const [expandedId, setExpandedId] = useState(null);
  const [assetDetail, setAssetDetail] = useState(null);

  const load = () => {
    setLoading(true);
    fetchAssets(filters).then(({ data }) => {
      if (data) setAssets(Array.isArray(data) ? data : data.assets || []);
      setLoading(false);
    });
  };

  useEffect(() => { load(); }, [filters]);

  const handleExpand = async (asset) => {
    if (expandedId === asset.id) {
      setExpandedId(null);
      setAssetDetail(null);
      return;
    }
    setExpandedId(asset.id);
    setAssetDetail(null);
    const { data } = await fetchAsset(asset.id);
    if (data) setAssetDetail(data);
  };

  const handleFilter = (key, value) => setFilters((prev) => ({ ...prev, [key]: value }));

  return (
    <div className="page">
      <h1 className="page-title">Assets</h1>

      <div className="filter-bar">
        <select className="filter-select" value={filters.status} onChange={(e) => handleFilter('status', e.target.value)}>
          <option value="">All Statuses</option>
          <option value="Online">Online</option>
          <option value="Offline">Offline</option>
          <option value="Unknown">Unknown</option>
        </select>
        <select className="filter-select" value={filters.is_new} onChange={(e) => handleFilter('is_new', e.target.value)}>
          <option value="">All Assets</option>
          <option value="true">Newly Discovered</option>
          <option value="false">Previously Known</option>
        </select>
      </div>

      {loading ? (
        <div className="loading-spinner"><div className="spinner" /></div>
      ) : assets.length === 0 ? (
        <div className="empty-state">No assets yet. Run a scan to build the inventory.</div>
      ) : (
        <div className="card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Type</th>
                <th>IP</th>
                <th>Status</th>
                <th>Web</th>
                <th>Ports</th>
                <th>TLS Expiry</th>
                <th>New</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => (
                <React.Fragment key={a.id}>
                  <tr className="clickable-row" onClick={() => handleExpand(a)}>
                    <td className="mono">{a.hostname}</td>
                    <td>{a.asset_type}</td>
                    <td className="mono">{a.ip || '—'}</td>
                    <td><StatusBadge status={a.status} /></td>
                    <td>{a.is_web ? '✓' : '—'}</td>
                    <td className="mono">{(a.open_ports || []).join(', ') || '—'}</td>
                    <td>{a.tls_expiry ? formatTime(a.tls_expiry) : '—'}</td>
                    <td>{a.is_new ? <span className="badge status-investigating">NEW</span> : ''}</td>
                  </tr>
                  {expandedId === a.id && (
                    <tr className="expanded-row">
                      <td colSpan={8}>
                        {!assetDetail ? (
                          <div className="loading-spinner"><div className="spinner" /></div>
                        ) : (
                          <div className="asset-detail">
                            <p className="card-text"><strong>{a.hostname}</strong> — last seen {formatTime(a.last_seen)}</p>
                            {(assetDetail.findings || []).length === 0 ? (
                              <div className="empty-state">No findings for this asset.</div>
                            ) : (
                              <table className="data-table compact">
                                <thead>
                                  <tr>
                                    <th>Severity</th>
                                    <th>Risk</th>
                                    <th>Finding</th>
                                    <th>Recommendation</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {assetDetail.findings.map((f) => (
                                    <tr key={f.id}>
                                      <td><SeverityBadge severity={f.severity} /></td>
                                      <td className="mono">{f.risk_score}</td>
                                      <td>
                                        <strong>{f.title}</strong>
                                        <div className="text-muted">{f.detail}</div>
                                      </td>
                                      <td className="text-muted">{f.recommendation}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
