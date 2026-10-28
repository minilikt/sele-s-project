import React from 'react';

const ALL_TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

const SCORE_TONE = (score) => {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
};

export default function AttackChain({ chain }) {
  if (!chain || !chain.stages || chain.stages.length === 0) {
    return (
      <div className="empty-state">
        This incident has no ATT&amp;CK-mapped activity, so no chain can be reconstructed.
      </div>
    );
  }

  const tactics = ALL_TACTICS;
  const covered = new Set(chain.stages.map((stage) => stage.tactic));
  const tone = SCORE_TONE(chain.score || 0);

  return (
    <div className="attack-chain">
      <div className="chain-header">
        <div className={`chain-score chain-score-${tone}`}>
          <span className="chain-score-value">{chain.score ?? 0}</span>
          <span className="chain-score-label">chain score</span>
        </div>
        <div className="chain-summary">
          <p className="card-text">{chain.summary}</p>
          <p className="chain-meta">
            {chain.covered_count} stage(s) · reached <strong>{chain.stage_reached}</strong> ·{' '}
            {chain.ordered ? 'in ATT&CK order' : 'out of order'}
          </p>
        </div>
      </div>

      <ol className="chain-stages" aria-label="Kill chain stages">
        {tactics.map((tactic) => {
          const stage = chain.stages.find((item) => item.tactic === tactic);
          const isCovered = covered.has(tactic);
          const isReached = chain.stage_reached === tactic;
          return (
            <li
              key={tactic}
              className={`chain-stage ${isCovered ? 'chain-stage-covered' : ''} ${
                isReached ? 'chain-stage-reached' : ''
              }`}
            >
              <span className="chain-stage-name">{tactic}</span>
              {stage && (
                <span className="chain-stage-detail">
                  {stage.alert_count} alert(s)
                  {stage.techniques?.length > 0 && ` · ${stage.techniques.join(', ')}`}
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
