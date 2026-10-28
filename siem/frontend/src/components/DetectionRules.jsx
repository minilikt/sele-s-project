import React, { useState, useEffect } from 'react';
import { fetchDetectionRules, updateRule, runDetection, fetchRuleYaml, reloadRules } from '../api';
import { hasRole } from '../session';
import SeverityBadge from './SeverityBadge';

export default function DetectionRules() {
  const isAdmin = hasRole('admin');
  const canRun = hasRole('analyst');
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedRow, setExpandedRow] = useState(null);
  const [runResult, setRunResult] = useState(null);
  const [running, setRunning] = useState(false);
  const [yamlCache, setYamlCache] = useState({});

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

  const handleReload = async () => {
    const { data, error } = await reloadRules();
    setRunResult(data || { error });
    load();
  };

  const handleConfigChange = async (rule, key, value) => {
    const config = { ...(rule.config || {}), [key]: value };
    await updateRule(rule.id, { config });
    load();
  };

  const showYaml = async (rule) => {
    if (yamlCache[rule.id]) return;
    const { data, error } = await fetchRuleYaml(rule.id);
    setYamlCache((prev) => ({ ...prev, [rule.id]: data || `Could not load YAML: ${error}` }));
  };

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Detection Rules</h1>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {isAdmin && (
            <button className="btn" onClick={handleReload}>
              ⟳ Reload Sigma Rules
            </button>
          )}
          <button className="btn btn-primary" onClick={handleRunAll} disabled={running || !canRun} title={canRun ? '' : 'Analyst role required'}>
            {running ? '⏳ Running...' : '▶ Run All Rules'}
          </button>
        </div>
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
                <th>Engine</th>
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
                    <td>
                      <span className={`badge ${rule.engine === 'sigma' ? 'status-open' : 'status-investigating'}`}>
                        {rule.engine === 'sigma' ? 'Sigma' : 'Python'}
                      </span>
                    </td>
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
                          disabled={!isAdmin}
                          title={isAdmin ? '' : 'Admin role required'}
                          onChange={() => handleToggle(rule)}
                        />
                        <span className="toggle-slider" />
                      </label>
                    </td>
                  </tr>
                  {expandedRow === idx && (
                    <tr className="expanded-row">
                      <td colSpan={7}>
                        <div className="rule-detail">
                          {rule.description && (
                            <p className="card-text">{rule.description}</p>
                          )}

                          {rule.tags && rule.tags.length > 0 && (
                            <div className="rule-tags">
                              {rule.tags.map((tag) => (
                                <span key={tag} className="badge badge-tag">{tag}</span>
                              ))}
                            </div>
                          )}

                          {rule.engine === 'sigma' ? (
                            <div className="rule-config">
                              <h4>Sigma Rule Source</h4>
                              {rule.has_source ? (
                                yamlCache[rule.id] ? (
                                  <pre className="json-block">{yamlCache[rule.id]}</pre>
                                ) : (
                                  <button className="btn" onClick={() => showYaml(rule)}>
                                    View YAML
                                  </button>
                                )
                              ) : (
                                <p className="card-text">Source not loaded.</p>
                              )}
                            </div>
                          ) : (
                            rule.config && (
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
                            )
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
