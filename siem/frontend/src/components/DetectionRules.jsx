import React, { useState, useEffect } from 'react';
import { fetchDetectionRules, updateRule, runDetection } from '../api';
import SeverityBadge from './SeverityBadge';

export default function DetectionRules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedRow, setExpandedRow] = useState(null);
  const [runResult, setRunResult] = useState(null);
  const [running, setRunning] = useState(false);

  const load = () => {
    setLoading(true);
    fetchDetectionRules().then(({ data }) => {
      if (data) setRules(Array.isArray(data) ? data : data.rules || []);
      setLoading(false);
    });
  };

  useEffect(() => { load(); }, []);

  const handleToggle = async (rule) => {
    const newEnabled = !rule.enabled;
    await updateRule(rule.id, { enabled: newEnabled });
    load();
  };

  const handleRunAll = async () => {
    setRunning(true);
    setRunResult(null);
    const { data, error } = await runDetection();
    setRunResult(data || { error });
    setRunning(false);
  };

  const handleConfigChange = async (rule, key, value) => {
    const config = { ...(rule.config || {}), [key]: value };
    await updateRule(rule.id, { config });
    load();
  };

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Detection Rules</h1>
        <button className="btn btn-primary" onClick={handleRunAll} disabled={running}>
          {running ? '⏳ Running...' : '▶ Run All Rules'}
        </button>
      </div>

      {runResult && (
        <div className="card result-card">
          <h3 className="card-title">Detection Results</h3>
          <pre className="json-block">{JSON.stringify(runResult, null, 2)}</pre>
        </div>
      )}

      {rules.length === 0 ? (
        <div className="empty-state">No detection rules configured.</div>
      ) : (
        <div className="card">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Severity</th>
                <th>MITRE Technique</th>
                <th>Status</th>
                <th>Toggle</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule, idx) => (
                <React.Fragment key={rule.id || idx}>
                  <tr
                    className="clickable-row"
                    onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                  >
                    <td className="mono">{rule.id}</td>
                    <td>{rule.name || rule.rule_name}</td>
                    <td><SeverityBadge severity={rule.severity} /></td>
                    <td className="mono">{rule.mitre_technique_id || rule.mitre_id || '—'}</td>
                    <td>
                      <span className={`badge ${rule.enabled ? 'status-open' : 'status-false-positive'}`}>
                        {rule.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <label className="toggle-switch">
                        <input
                          type="checkbox"
                          checked={rule.enabled}
                          onChange={() => handleToggle(rule)}
                        />
                        <span className="toggle-slider" />
                      </label>
                    </td>
                  </tr>
                  {expandedRow === idx && (
                    <tr className="expanded-row">
                      <td colSpan={6}>
                        <div className="rule-detail">
                          {rule.description && (
                            <p className="card-text">{rule.description}</p>
                          )}
                          {rule.config && (
                            <div className="rule-config">
                              <h4>Configuration</h4>
                              {Object.entries(rule.config).map(([key, val]) => (
                                <div className="config-field" key={key}>
                                  <label className="config-label">{key}</label>
                                  <input
                                    type={typeof val === 'number' ? 'number' : 'text'}
                                    className="config-input"
                                    value={val}
                                    onChange={(e) =>
                                      handleConfigChange(
                                        rule,
                                        key,
                                        typeof val === 'number'
                                          ? Number(e.target.value)
                                          : e.target.value
                                      )
                                    }
                                  />
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
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
