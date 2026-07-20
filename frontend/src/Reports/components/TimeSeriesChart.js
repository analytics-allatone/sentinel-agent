import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./TimeSeriesChart.css";

// Internal SVG coordinate width — the SVG scales to 100% of its container,
// so all math is done in this fixed coordinate space and rendered responsively.
const W = 1000;

function fmtTime(t) {
  const m = String(t || "").match(/T(\d{2}):(\d{2}):(\d{2})/);
  if (m) return `${m[1]}:${m[2]}:${m[3]}`;
  return String(t || "");
}
function fmtDateTime(t) {
  const d = String(t || "").match(/(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/);
  if (d) return `${d[1]}/${d[2]}/${d[3]} ${d[4]}:${d[5]}:${d[6]}`;
  return fmtTime(t);
}

/**
 * Interactive, dependency-free time-series chart.
 *
 * props:
 *  - series : [{ key, name, color, area?, data: [{ t, value }] }]
 *  - height : plot area height in SVG units (default 240)
 *  - yMax   : top of the value axis (default 100)
 *  - unit   : value suffix in the tooltip / axis (default "%")
 *  - title  : optional heading
 *  - minimap: show the bottom range strip (default true)
 *
 * Interactions: mouse-wheel to zoom, drag to pan, buttons to zoom/reset,
 * drag the mini-map window (or its edges) to pan / zoom — trading-app style.
 */
export default function TimeSeriesChart({
  series = [],
  height = 240,
  yMax = 100,
  unit = "%",
  title,
  minimap = true,
}) {
  const svgRef = useRef(null);
  const dragRef = useRef(null);

  const N = useMemo(
    () => series.reduce((m, s) => Math.max(m, (s.data || []).length), 0),
    [series]
  );

  const [view, setView] = useState({ start: 0, end: Math.max(1, N - 1) });
  const [hover, setHover] = useState(null); // hovered index

  // reset the viewport whenever the underlying data size changes
  useEffect(() => {
    setView({ start: 0, end: Math.max(1, N - 1) });
    setHover(null);
  }, [N]);

  // ── layout (SVG units) ───────────────────────────────────────
  const plotL = 46;
  const plotR = W - 14;
  const plotW = plotR - plotL;
  const plotT = 12;
  const chartH = height;
  const plotB = plotT + chartH;
  const mmGap = 34;
  const mmT = plotB + mmGap;
  const mmH = minimap ? 46 : 0;
  const mmB = mmT + mmH;
  const totalH = (minimap ? mmB : plotB) + 26;

  const span = Math.max(1e-6, view.end - view.start);
  const domainMax = Math.max(1, N - 1);

  const xForIndex = (i) => plotL + ((i - view.start) / span) * plotW;
  const yForVal = (v) => plotB - (Math.min(yMax, Math.max(0, Number(v) || 0)) / yMax) * chartH;
  const xForFull = (i) => plotL + (i / domainMax) * plotW;
  const mmYForVal = (v) => mmB - (Math.min(yMax, Math.max(0, Number(v) || 0)) / yMax) * mmH;

  const clampView = useCallback(
    (s, e) => {
      let ns = s;
      let ne = e;
      const minSpan = Math.min(3, domainMax);
      if (ne - ns < minSpan) {
        const c = (ns + ne) / 2;
        ns = c - minSpan / 2;
        ne = c + minSpan / 2;
      }
      if (ns < 0) {
        ne -= ns;
        ns = 0;
      }
      if (ne > domainMax) {
        ns -= ne - domainMax;
        ne = domainMax;
      }
      if (ns < 0) ns = 0;
      return { start: ns, end: ne };
    },
    [domainMax]
  );

  // ── coordinate helpers ───────────────────────────────────────
  const toSvg = (clientX, clientY) => {
    const r = svgRef.current.getBoundingClientRect();
    return {
      x: ((clientX - r.left) / r.width) * W,
      y: ((clientY - r.top) / r.height) * totalH,
    };
  };
  const svgXToIndex = (x) => view.start + ((x - plotL) / plotW) * span;
  const svgXToFullIndex = (x) => ((x - plotL) / plotW) * domainMax;

  // ── zoom (buttons) ───────────────────────────────────────────
  const zoomBy = (factor) => {
    const center = (view.start + view.end) / 2;
    setView(clampView(center - (center - view.start) * factor, center + (view.end - center) * factor));
  };
  const resetView = () => setView({ start: 0, end: domainMax });

  // ── wheel zoom (native non-passive listener) ─────────────────
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return undefined;
    const onWheel = (e) => {
      const { x, y } = toSvg(e.clientX, e.clientY);
      if (y > plotB + 4) return; // ignore wheel over the mini-map
      e.preventDefault();
      const ci = Math.min(domainMax, Math.max(0, svgXToIndex(x)));
      const factor = e.deltaY > 0 ? 1.18 : 1 / 1.18;
      setView(clampView(ci - (ci - view.start) * factor, ci + (view.end - ci) * factor));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, span, N]);

  // ── pointer (pan + minimap drag + hover) ─────────────────────
  const onPointerDown = (e) => {
    if (!N) return;
    const { x, y } = toSvg(e.clientX, e.clientY);
    svgRef.current.setPointerCapture(e.pointerId);

    if (minimap && y >= mmT - 6 && y <= mmB + 6) {
      const wx0 = xForFull(view.start);
      const wx1 = xForFull(view.end);
      let mode = "mm-move";
      if (Math.abs(x - wx0) <= 10) mode = "mm-resize-l";
      else if (Math.abs(x - wx1) <= 10) mode = "mm-resize-r";
      else if (x < wx0 || x > wx1) {
        // jump: center the current window on the click
        const fi = svgXToFullIndex(x);
        const half = span / 2;
        setView(clampView(fi - half, fi + half));
        mode = "mm-move";
      }
      dragRef.current = { mode, lastFull: svgXToFullIndex(x) };
      setHover(null);
      return;
    }

    if (y >= plotT && y <= plotB) {
      dragRef.current = { mode: "pan", lastX: x, view: { ...view } };
    }
  };

  const onPointerMove = (e) => {
    if (!N) return;
    const { x, y } = toSvg(e.clientX, e.clientY);
    const drag = dragRef.current;

    if (!drag) {
      if (y >= plotT && y <= plotB && x >= plotL && x <= plotR) {
        const idx = Math.round(Math.min(view.end, Math.max(view.start, svgXToIndex(x))));
        setHover(idx);
      } else {
        setHover(null);
      }
      return;
    }

    if (drag.mode === "pan") {
      const dIndex = ((x - drag.lastX) / plotW) * (drag.view.end - drag.view.start);
      setView(clampView(drag.view.start - dIndex, drag.view.end - dIndex));
    } else if (drag.mode === "mm-move") {
      const fi = svgXToFullIndex(x);
      const d = fi - drag.lastFull;
      dragRef.current = { ...drag, lastFull: fi };
      setView((v) => clampView(v.start + d, v.end + d));
    } else if (drag.mode === "mm-resize-l") {
      setView((v) => clampView(Math.min(svgXToFullIndex(x), v.end - 2), v.end));
    } else if (drag.mode === "mm-resize-r") {
      setView((v) => clampView(v.start, Math.max(svgXToFullIndex(x), v.start + 2)));
    }
  };

  const endDrag = (e) => {
    if (dragRef.current && svgRef.current) {
      try {
        svgRef.current.releasePointerCapture(e.pointerId);
      } catch (_) {}
    }
    dragRef.current = null;
  };

  // ── path builders ────────────────────────────────────────────
  const pathFor = (data, area) => {
    const i0 = Math.max(0, Math.floor(view.start) - 1);
    const i1 = Math.min(domainMax, Math.ceil(view.end) + 1);
    let d = "";
    let first = null;
    let last = null;
    for (let i = i0; i <= i1; i++) {
      const p = data[i];
      if (!p) continue;
      const x = xForIndex(i);
      const yy = yForVal(p.value);
      d += `${d === "" ? "M" : "L"}${x.toFixed(1)} ${yy.toFixed(1)} `;
      if (first === null) first = x;
      last = x;
    }
    if (area && d && first !== null) {
      d += `L${last.toFixed(1)} ${plotB} L${first.toFixed(1)} ${plotB} Z`;
    }
    return d;
  };

  const mmPathFor = (data) => {
    let d = "";
    let first = null;
    let last = null;
    for (let i = 0; i <= domainMax; i++) {
      const p = data[i];
      if (!p) continue;
      const x = xForFull(i);
      const yy = mmYForVal(p.value);
      d += `${d === "" ? "M" : "L"}${x.toFixed(1)} ${yy.toFixed(1)} `;
      if (first === null) first = x;
      last = x;
    }
    if (d && first !== null) d += `L${last.toFixed(1)} ${mmB} L${first.toFixed(1)} ${mmB} Z`;
    return d;
  };

  // ── axis ticks ───────────────────────────────────────────────
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(yMax * f));
  const primary = series[0];
  const baseData = (primary && primary.data) || [];

  const xTicks = useMemo(() => {
    const ticks = [];
    const steps = 6;
    for (let k = 0; k <= steps; k++) {
      const idx = Math.round(view.start + span * (k / steps));
      const p = baseData[idx];
      if (p) ticks.push({ x: xForIndex(idx), label: fmtTime(p.t) });
    }
    return ticks;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, span, N]);

  // ── hover tooltip data ───────────────────────────────────────
  const hoverT = hover != null && baseData[hover] ? baseData[hover].t : null;
  const hoverX = hover != null ? xForIndex(hover) : null;
  const tipLeftPct = hoverX != null ? (hoverX / W) * 100 : 0;
  const tipOnRight = tipLeftPct > 62;

  const areaSeries = series.filter((s) => s.area);

  return (
    <div className="tsc">
      <div className="tsc-head">
        <div className="tsc-legend">
          {series.map((s) => (
            <span className="tsc-leg" key={s.key}>
              <i style={{ background: s.color }} />
              {s.name}
            </span>
          ))}
        </div>
        <div className="tsc-tools">
          <button type="button" className="tsc-btn" onClick={() => zoomBy(0.6)} title="Zoom in" aria-label="Zoom in">＋</button>
          <button type="button" className="tsc-btn" onClick={() => zoomBy(1.6)} title="Zoom out" aria-label="Zoom out">－</button>
          <button type="button" className="tsc-btn tsc-btn-txt" onClick={resetView} title="Reset zoom">Reset</button>
        </div>
      </div>

      <div className="tsc-plot-wrap">
        <svg
          ref={svgRef}
          className="tsc-svg"
          viewBox={`0 0 ${W} ${totalH}`}
          preserveAspectRatio="none"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
          onPointerLeave={() => setHover(null)}
        >
          <defs>
            {areaSeries.map((s) => (
              <linearGradient id={`tsc-grad-${s.key}`} key={s.key} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={s.color} stopOpacity="0.16" />
                <stop offset="100%" stopColor={s.color} stopOpacity="0.01" />
              </linearGradient>
            ))}
            <clipPath id="tsc-clip">
              <rect x={plotL} y={plotT} width={plotW} height={chartH} />
            </clipPath>
          </defs>

          {/* y grid + labels */}
          {yTicks.map((v) => {
            const y = yForVal(v);
            return (
              <g key={v}>
                <line x1={plotL} y1={y} x2={plotR} y2={y} className="tsc-grid" />
                <text x={plotL - 8} y={y + 3} className="tsc-ylabel" textAnchor="end">
                  {v}
                  {unit}
                </text>
              </g>
            );
          })}

          {/* x labels */}
          {xTicks.map((t, i) => (
            <text key={i} x={t.x} y={plotB + 16} className="tsc-xlabel" textAnchor="middle">
              {t.label}
            </text>
          ))}

          {/* series */}
          <g clipPath="url(#tsc-clip)">
            {series.map((s) => (
              <g key={s.key}>
                {s.area && <path d={pathFor(s.data, true)} fill={`url(#tsc-grad-${s.key})`} stroke="none" />}
                <path
                  d={pathFor(s.data, false)}
                  fill="none"
                  stroke={s.color}
                  strokeWidth="2"
                  strokeLinejoin="round"
                  strokeLinecap="round"
                />
              </g>
            ))}

            {/* crosshair + hover dots */}
            {hover != null && hoverX != null && (
              <g>
                <line x1={hoverX} y1={plotT} x2={hoverX} y2={plotB} className="tsc-cross" />
                {series.map((s) => {
                  const p = s.data[hover];
                  if (!p) return null;
                  return <circle key={s.key} cx={hoverX} cy={yForVal(p.value)} r="4" fill={s.color} stroke="#fff" strokeWidth="2" />;
                })}
              </g>
            )}
          </g>

          {/* plot frame */}
          <rect x={plotL} y={plotT} width={plotW} height={chartH} className="tsc-frame" />

          {/* ── mini-map ── */}
          {minimap && (
            <g>
              <rect x={plotL} y={mmT} width={plotW} height={mmH} className="tsc-mm-bg" />
              {primary && <path d={mmPathFor(baseData)} className="tsc-mm-area" fill={primary.color} fillOpacity="0.12" stroke={primary.color} strokeWidth="1" />}
              {/* dim outside the window */}
              <rect x={plotL} y={mmT} width={Math.max(0, xForFull(view.start) - plotL)} height={mmH} className="tsc-mm-dim" />
              <rect x={xForFull(view.end)} y={mmT} width={Math.max(0, plotR - xForFull(view.end))} height={mmH} className="tsc-mm-dim" />
              {/* window */}
              <rect
                x={xForFull(view.start)}
                y={mmT}
                width={Math.max(2, xForFull(view.end) - xForFull(view.start))}
                height={mmH}
                className="tsc-mm-window"
              />
              <rect x={xForFull(view.start) - 3} y={mmT} width="6" height={mmH} className="tsc-mm-handle" />
              <rect x={xForFull(view.end) - 3} y={mmT} width="6" height={mmH} className="tsc-mm-handle" />
            </g>
          )}
        </svg>

        {/* HTML tooltip overlaid on the SVG (positioned by %) */}
        {hover != null && hoverT != null && (
          <div
            className={`tsc-tip ${tipOnRight ? "left" : "right"}`}
            style={{ left: `${tipLeftPct}%`, top: `${(plotT / totalH) * 100}%` }}
          >
            <div className="tsc-tip-time">{fmtDateTime(hoverT)}</div>
            {series.map((s) => {
              const p = s.data[hover];
              return (
                <div className="tsc-tip-row" key={s.key}>
                  <span className="tsc-tip-key">
                    <i style={{ background: s.color }} />
                    {s.name}
                  </span>
                  <span className="tsc-tip-val">{p ? `${(Number(p.value) || 0).toFixed(1)}${unit}` : "—"}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="tsc-hint">Scroll to zoom · drag to pan · drag the strip below to move the window</div>
    </div>
  );
}
