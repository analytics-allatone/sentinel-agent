import React from "react";

/**
 * props:
 *  - label        : left-hand label
 *  - value        : 0-100, drives bar width and (unless overridden) color
 *  - count        : optional right-hand number/text
 *  - displayValue : alias for `count` (Capacity report naming)
 *  - colorOverride: "green" | "amber" | "red" | "blue" — forces a colour
 *  - dangerAt     : value strictly above this => red   (default 85)
 *  - warnAt       : value at/above this       => amber (default 70)
 *
 * auto colour (for "bad" metrics like cpu / failures):
 *   value > dangerAt   => red
 *   value >= warnAt    => amber
 *   otherwise          => green
 */
const COLORS = {
  green: "#5a9216",
  amber: "#e08b0a",
  red: "#d64545",
  blue: "#2b7fd0",
};

// tint of the fill's own hue for the unfilled track, so the severity of a bar
// reads across its whole length rather than only the filled part
function tint(color, alpha) {
  const m = /^#([0-9a-f]{6})$/i.exec(color || "");
  if (!m) return "rgba(11, 11, 11, 0.06)";
  const n = parseInt(m[1], 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`;
}

export default function ProgressBar({
  label,
  value = 0,
  count,
  displayValue,
  colorOverride,
  dangerAt = 85,
  warnAt = 70,
}) {
  const pct = Math.max(0, Math.min(100, Number(value) || 0));

  const autoColor = (v) => {
    if (v > dangerAt) return COLORS.red;
    if (v >= warnAt) return COLORS.amber;
    return COLORS.green;
  };

  const color = colorOverride ? COLORS[colorOverride] || colorOverride : autoColor(pct);
  const right = displayValue != null ? displayValue : count;

  return (
    <div className="pbar-row">
      <div className="pbar-head">
        <span className="pbar-label">{label}</span>
        {right != null && right !== "" && <span className="pbar-count">{right}</span>}
      </div>
      <div className="pbar-track" style={{ background: tint(color, 0.14) }}>
        <div className="pbar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}
