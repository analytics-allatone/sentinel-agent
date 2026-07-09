import React from "react";

/**
 * Pure-CSS flex bar chart — no chart library.
 *
 * props:
 *  - data           : [{ day, value }]
 *  - height         : bar area height in px (default 40)
 *  - dangerThreshold: value >= this => red   (default 75)
 *  - warnThreshold  : value >= this => amber (default 60)
 */
export default function SparklineBar({
  data = [],
  height = 40,
  dangerThreshold = 75,
  warnThreshold = 60,
}) {
  const max = Math.max(1, ...data.map((d) => Number(d.value) || 0));

  const colorFor = (v) => {
    if (v >= dangerThreshold) return "#E24B4A";
    if (v >= warnThreshold) return "#EF9F27";
    return "#9FE1CB";
  };

  return (
    <div className="spark">
      <div className="spark-bars" style={{ height }}>
        {data.map((d, i) => {
          const h = Math.max(3, ((Number(d.value) || 0) / max) * 100);
          return (
            <div className="spark-col" key={i}>
              <div
                className="spark-bar"
                style={{ height: `${h}%`, background: colorFor(Number(d.value) || 0) }}
              />
            </div>
          );
        })}
      </div>
      <div className="spark-labels">
        {data.map((d, i) => (
          <span className="spark-label" key={i}>
            {d.day}
          </span>
        ))}
      </div>
    </div>
  );
}
