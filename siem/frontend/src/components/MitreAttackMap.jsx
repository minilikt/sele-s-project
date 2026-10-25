import React, { useState, useEffect } from 'react';
import { fetchMitreCoverage, fetchMitreTechniques, fetchMitreTechnique } from '../api';
import SeverityBadge from './SeverityBadge';

const TACTIC_ORDER = [
  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command and Control', 'Exfiltration', 'Impact',
];

export default function MitreAttackMap() {
  const [techniques, setTechniques] = useState([]);
  const [coverage, setCoverage] = useState(null);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([fetchMitreTechniques(), fetchMitreCoverage()]).then(
      ([techRes, covRes]) => {
        if (techRes.data) {
          const list = Array.isArray(techRes.data) ? techRes.data : techRes.data.techniques || [];
          setTechniques(list);
        }
        if (covRes.data) setCoverage(covRes.data);
        setLoading(false);
      }
    );
  }, []);

  const handleTechniqueClick = async (tech) => {
    setSelectedTechnique(tech);
    const { data } = await fetchMitreTechnique(tech.id || tech.technique_id);
    if (data) setDetail(data);
  };

  if (loading) return <div className="loading-spinner"><div className="spinner" /></div>;

  // Group techniques by tactic
  const tacticMap = {};
  TACTIC_ORDER.forEach((t) => (tacticMap[t] = []));

  techniques.forEach((tech) => {
    const tactic = tech.tactic || tech.tactics?.[0] || 'Other';
    if (!tacticMap[tactic]) tacticMap[tactic] = [];
    tacticMap[tactic].push(tech);
  });

  const maxAlerts = Math.max(
    1,
    ...techniques.map((t) => t.alert_count || t.alerts_count || 0)
  );

  return (
    <div className="page">
      <h1 className="page-title">MITRE ATT&CK Coverage</h1>

      <div className="mitre-layout">
        <div className="mitre-matrix">
          {TACTIC_ORDER.filter((t) => tacticMap[t] && tacticMap[t].length > 0).map(
            (tactic) => (
              <div className="mitre-tactic-col" key={tactic}>
                <div className="mitre-tactic-header">{tactic}</div>
                {tacticMap[tactic].map((tech) => {
                  const count = tech.alert_count || tech.alerts_count || 0;
                  const intensity = Math.min(1, count / maxAlerts);
                  const isSelected =
                    selectedTechnique &&
                    (selectedTechnique.id || selectedTechnique.technique_id) ===
                      (tech.id || tech.technique_id);
                  return (
                    <div
                      key={tech.id || tech.technique_id}
                      className={`mitre-technique-cell ${isSelected ? 'selected' : ''}`}
                      style={{
                        backgroundColor: count > 0
                          ? `rgba(59, 130, 246, ${0.15 + intensity * 0.6})`
                          : 'var(--bg-card)',
                      }}
                      onClick={() => handleTechniqueClick(tech)}
                    >
                      <span className="mitre-tech-id">
                        {tech.id || tech.technique_id}
                      </span>
                      <span className="mitre-tech-name">
                        {tech.name || tech.technique_name}
                      </span>
                      {count > 0 && (
                        <span className="mitre-tech-count">{count}</span>
                      )}
                    </div>
                  );
                })}
              </div>
            )
          )}
        </div>

        {/* Detail Panel */}
        {selectedTechnique && (
          <div className="mitre-detail-panel card">
            <h2 className="card-title">
              {selectedTechnique.id || selectedTechnique.technique_id} —{' '}
              {selectedTechnique.name || selectedTechnique.technique_name}
            </h2>

            {(detail?.description || selectedTechnique.description) && (
              <div className="detail-section">
                <h3>Description</h3>
                <p>{detail?.description || selectedTechnique.description}</p>
              </div>
            )}

            {detail?.detection_guidance && (
              <div className="detail-section">
                <h3>Detection Guidance</h3>
                <p>{detail.detection_guidance}</p>
              </div>
            )}

            {detail?.investigation_steps && (
              <div className="detail-section">
                <h3>Investigation Steps</h3>
                <ul>
                  {(Array.isArray(detail.investigation_steps)
                    ? detail.investigation_steps
                    : [detail.investigation_steps]
                  ).map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ul>
              </div>
            )}

            {detail?.alerts && detail.alerts.length > 0 && (
              <div className="detail-section">
                <h3>Current Alerts ({detail.alerts.length})</h3>
                {detail.alerts.map((a, i) => (
                  <div key={i} className="mitre-alert-item">
                    <span>{a.rule_name || a.title}</span>
                    <SeverityBadge severity={a.severity} />
                  </div>
                ))}
              </div>
            )}

            <button
              className="btn btn-secondary"
              onClick={() => { setSelectedTechnique(null); setDetail(null); }}
            >
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
