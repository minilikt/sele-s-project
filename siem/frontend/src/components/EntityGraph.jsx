import React, { useMemo } from 'react';

const TYPE_COLOUR = {
  user: '#38bdf8',
  host: '#a78bfa',
  ip: '#f59e0b',
};

const WIDTH = 680;
const HEIGHT = 380;
const RADIUS = 22;

/**
 * Compact circular entity graph.
 *
 * A force-directed layout would look nicer, but a deterministic circle keeps the
 * graph stable between renders (no jitter when a screenshot is taken) and needs
 * no extra dependency.
 */
export default function EntityGraph({ graph }) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];

  const positioned = useMemo(() => {
    const centreX = WIDTH / 2;
    const centreY = HEIGHT / 2;
    const ring = Math.min(centreX, centreY) - 70;
    return nodes.map((node, index) => {
      const angle = (2 * Math.PI * index) / Math.max(1, nodes.length) - Math.PI / 2;
      return {
        ...node,
        x: centreX + ring * Math.cos(angle),
        y: centreY + ring * Math.sin(angle),
      };
    });
  }, [nodes]);

  const positions = useMemo(
    () => Object.fromEntries(positioned.map((node) => [node.key, node])),
    [positioned]
  );

  if (nodes.length === 0) {
    return <div className="empty-state">No entities recorded for this incident.</div>;
  }

  const maxWeight = Math.max(...edges.map((edge) => edge.weight), 1);

  return (
    <div className="entity-graph">
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img" aria-label="Entity relationship graph">
        {edges.map((edge, index) => {
          const source = positions[edge.source];
          const target = positions[edge.target];
          if (!source || !target) return null;
          return (
            <line
              key={`${edge.source}-${edge.target}-${index}`}
              x1={source.x}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              stroke="#334155"
              strokeWidth={1 + (edge.weight / maxWeight) * 2}
              strokeOpacity={0.35 + (edge.weight / maxWeight) * 0.5}
            />
          );
        })}

        {positioned.map((node) => (
          <g key={node.key}>
            <circle
              cx={node.x}
              cy={node.y}
              r={RADIUS}
              fill={`${TYPE_COLOUR[node.type] || '#94a3b8'}22`}
              stroke={TYPE_COLOUR[node.type] || '#94a3b8'}
              strokeWidth={2}
            />
            <text
              x={node.x}
              y={node.y + 4}
              textAnchor="middle"
              fontSize="10"
              fill="#e2e8f0"
            >
              {node.alert_count}
            </text>
            <text
              x={node.x}
              y={node.y + RADIUS + 14}
              textAnchor="middle"
              fontSize="10"
              fill="#94a3b8"
            >
              {node.value.length > 18 ? `${node.value.slice(0, 16)}…` : node.value}
            </text>
          </g>
        ))}
      </svg>

      <div className="graph-legend">
        {Object.entries(TYPE_COLOUR).map(([type, colour]) => (
          <span key={type} className="legend-item">
            <span className="legend-dot" style={{ background: colour }} />
            {type}
          </span>
        ))}
        <span className="legend-item legend-note">number inside a node = related alerts</span>
      </div>
    </div>
  );
}
