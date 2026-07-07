import React from "react";

/**
 * props:
 *  - scores: [{ key, label, value }] — value is a 0-100 compliance score
 *
 * colour (higher is better):
 *   >=90 => green
 *   75-89 => amber
 *   <75  => red
 */
function scoreColor(value) {
  if (value >= 90) return "#5a9216";
  if (value >= 75) return "#e08b0a";
  return "#d64545";
}

export default function CriteriaScores({ scores = [] }) {
  return (
    <div className="criteria-list">
      {scores.map((s) => {
        const color = scoreColor(s.value);
        return (
          <div className="criteria-row" key={s.key}>
            <span className="criteria-accent" style={{ background: color }} />
            <span className="criteria-label">{s.label}</span>
            <div className="criteria-track">
              <div
                className="criteria-fill"
                style={{ width: `${Math.min(100, s.value)}%`, background: color }}
              />
            </div>
            <span className="criteria-pct" style={{ color }}>
              {s.value}%
            </span>
          </div>
        );
      })}
    </div>
  );
}
