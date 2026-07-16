import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Area,
  AreaChart,
  Brush,
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { absoluteOverviewUrl, fetchOverview } from "./capacityApi";
import {
  buildRows,
  clampRange as clampToBounds,
  findGaps,
  formatClock,
  formatDuration,
  formatFull,
} from "./capacityTransform";
import { CHART_CHROME, GAP_COLOR, SERIES_COLORS } from "./colors";
import "./CapacityDashboard.css";

// ── zoom/pan constants ─────────────────────────────────────────
const MIN_SPAN = 8; // never zoom tighter than 8 samples
const ZOOM_IN = 0.8;
const ZOOM_OUT = 1.25;
const MIN_BOX_PX = 12; // ignore box-zoom smudges

// Recharts lays the plot out inside these; the pointer maths needs the plot
// box, not the container box, or the cursor anchor drifts.
const CHART_MARGIN = { top: 10, right: 14, bottom: 4, left: 4 };
const Y_AXIS_WIDTH = 44;
const PLOT_INSET_LEFT = CHART_MARGIN.left + Y_AXIS_WIDTH;
const PLOT_INSET_RIGHT = CHART_MARGIN.right;

// ── pane definitions ───────────────────────────────────────────
// Storage steps because its jumps (82.4 -> 86.3 -> 82.4) are real deploy /
// cleanup events; smoothing them would state something untrue.
//
// A line's `key` is both its row field and its slot in the palette, so colour
// follows the entity and stays put when the theme changes.
const PANES = [
  {
    id: "host-cpu",
    title: "Host CPU",
    unit: "%",
    lines: [{ key: "cpu", name: "Host CPU", type: "monotone" }],
  },
  {
    id: "host-mem",
    title: "Host memory and storage",
    unit: "%",
    lines: [
      { key: "mem", name: "Host memory", type: "monotone" },
      { key: "sto", name: "Storage", type: "stepAfter" },
    ],
  },
  {
    id: "agent",
    title: "Agent CPU and memory",
    unit: "%",
    lines: [
      { key: "acpu", name: "Agent CPU", type: "monotone" },
      { key: "amem", name: "Agent memory", type: "monotone" },
    ],
  },
  // Mbps, not percent — hence its own pane. Sharing the 0-100 axis above would
  // flatten a 0.04 Mbps line onto the baseline and imply it is a percentage.
  {
    id: "agent-bw",
    title: "Agent bandwidth",
    unit: "Mbps",
    lines: [{ key: "bw", name: "Agent bandwidth", type: "monotone" }],
  },
];

/**
 * Values on this page span 0-100 percentages and sub-1 Mbps readings, so the
 * decimal count follows the magnitude — %.toFixed(1) would render 0.04 Mbps as
 * "0.0" and the whole bandwidth pane would read as zero.
 */
function formatValue(value, unit) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  const abs = Math.abs(n);
  const decimals = abs >= 10 ? 1 : abs >= 1 ? 2 : 3;
  return unit === "%" ? `${n.toFixed(decimals)}%` : `${n.toFixed(decimals)} ${unit}`;
}

/** Axis ticks: same magnitude rule, without the unit suffix. */
function formatTick(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "";
  if (n === 0) return "0"; // a bare zero, never "0.00" — the baseline on a % axis
  const abs = Math.abs(n);
  if (abs >= 10) return String(Math.round(n));
  if (abs >= 1) return n.toFixed(1);
  return n.toFixed(2);
}

/** Resolve a pane's lines against the active theme's palette. */
function paintLines(lines, theme) {
  const palette = SERIES_COLORS[theme];
  return lines.map((line) => ({ ...line, color: palette[line.key] }));
}

// ── print layout ───────────────────────────────────────────────
// A4 portrait at 96dpi minus 12mm margins is ~715px of usable width. The print
// charts are given explicit pixel sizes rather than a ResponsiveContainer:
// ResponsiveContainer measures the DOM through a ResizeObserver, which does not
// re-measure for the print box, so it would print the charts at screen size.
const PRINT_W = 700;
const PRINT_H = 430;

const STATS = [
  { key: "avg_cpu_percent", label: "Avg CPU", unit: "%", modifier: "cpu" },
  { key: "avg_memory", label: "Avg memory", unit: "MB", modifier: "mem" },
  { key: "avg_agent_cpu_percent", label: "Avg Agent CPU", unit: "%", modifier: "acpu" },
  { key: "avg_agent_memory", label: "Avg Agent memory", unit: "%", modifier: "amem" },
  { key: "avg_bandwidth_mbps", label: "Avg Bandwidth", unit: "Mbps", modifier: "bw" },
];

// ── range helpers ──────────────────────────────────────────────
function clamp01(n) {
  return Math.min(1, Math.max(0, n));
}

/** Bind the shared MIN_SPAN to the pure clamp from capacityTransform. */
function clampRange(start, end, lastIndex) {
  return clampToBounds(start, end, lastIndex, MIN_SPAN);
}

const THEME_KEY = "capacity-dash-theme";

/** Saved choice wins; otherwise follow the OS. */
function initialTheme() {
  try {
    const saved = window.localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch (_) {
    /* storage can be blocked; fall through to the OS preference */
  }
  try {
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
      return "light";
    }
  } catch (_) {
    /* matchMedia missing */
  }
  return "dark";
}

function defaultLocalRange() {
  const now = new Date();
  const from = new Date(now.getTime() - 864e5);
  const iso = (d, h, m) =>
    `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(
      2,
      "0"
    )}T${h}:${m}`;
  return { from: iso(from, "00", "00"), to: iso(now, "23", "59") };
}

// ── zoom / pan / box-select ────────────────────────────────────
function useZoomPan({ range, setRange, lastIndex }) {
  const containerRef = useRef(null);
  const dragRef = useRef(null);
  const rangeRef = useRef(range);
  rangeRef.current = range;

  const [selection, setSelection] = useState(null);

  const geometry = useCallback(() => {
    const rect = containerRef.current.getBoundingClientRect();
    const left = rect.left + PLOT_INSET_LEFT;
    const width = Math.max(1, rect.width - PLOT_INSET_LEFT - PLOT_INSET_RIGHT);
    return { rect, left, width };
  }, []);

  // Wheel must be a native non-passive listener: React's onWheel is passive, so
  // preventDefault there is ignored and the page scrolls under the cursor.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return undefined;

    const onWheel = (event) => {
      if (lastIndex <= 0) return;
      event.preventDefault();

      const { left, width } = geometry();
      const [start, end] = rangeRef.current;
      // The sample under the pointer has to stay under the pointer, so zoom
      // about that index rather than the middle of the pane.
      const anchor = start + clamp01((event.clientX - left) / width) * (end - start);
      const factor = event.deltaY < 0 ? ZOOM_IN : ZOOM_OUT;

      setRange(
        clampRange(anchor - (anchor - start) * factor, anchor + (end - anchor) * factor, lastIndex)
      );
    };

    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [geometry, lastIndex, setRange]);

  const onPointerDown = (event) => {
    if (lastIndex <= 0 || event.button !== 0) return;
    const { rect } = geometry();
    const x = event.clientX - rect.left;

    try {
      containerRef.current.setPointerCapture(event.pointerId);
    } catch (_) {
      /* capture is best-effort */
    }

    if (event.shiftKey) {
      dragRef.current = { mode: "box", x0: x };
      setSelection({ x0: x, x1: x });
    } else {
      dragRef.current = { mode: "pan", startX: event.clientX, range: rangeRef.current };
    }
  };

  const onPointerMove = (event) => {
    const drag = dragRef.current;
    if (!drag) return;
    const { rect, width } = geometry();

    if (drag.mode === "pan") {
      const [start, end] = drag.range;
      const deltaIndex = ((event.clientX - drag.startX) / width) * (end - start);
      setRange(clampRange(start - deltaIndex, end - deltaIndex, lastIndex));
    } else {
      const x = event.clientX - rect.left;
      setSelection((current) => (current ? { x0: current.x0, x1: x } : current));
    }
  };

  const finishDrag = (event) => {
    const drag = dragRef.current;
    dragRef.current = null;
    try {
      containerRef.current.releasePointerCapture(event.pointerId);
    } catch (_) {
      /* nothing captured */
    }
    if (!drag || drag.mode !== "box") return;

    const { rect, left, width } = geometry();
    const x = event.clientX - rect.left;
    const x0 = Math.min(drag.x0, x);
    const x1 = Math.max(drag.x0, x);
    setSelection(null);

    if (x1 - x0 < MIN_BOX_PX) return;

    const [start, end] = rangeRef.current;
    const toIndex = (px) => start + clamp01((px + rect.left - left) / width) * (end - start);
    const nextStart = toIndex(x0);
    const nextEnd = toIndex(x1);
    if (nextEnd - nextStart < MIN_SPAN) return;

    setRange(clampRange(nextStart, nextEnd, lastIndex));
  };

  const onDoubleClick = () => setRange([0, Math.max(0, lastIndex)]);

  return {
    containerRef,
    selection,
    handlers: {
      onPointerDown,
      onPointerMove,
      onPointerUp: finishDrag,
      onPointerCancel: finishDrag,
      onDoubleClick,
    },
  };
}

/**
 * A sample whose neighbours are both null has nothing to draw a segment to, so
 * with connectNulls={false} it renders as literally nothing. That happens
 * whenever a series reports on a coarser cadence than the joined timeline — the
 * agent series against the host series, for instance — and it silently blanks
 * the whole pane. Dots are drawn for those points only: a lone reading stays
 * visible, and a run of samples still costs zero dots.
 */
function makeDotRenderer(dataKey, color, data) {
  return function renderDot(props) {
    const { cx, cy, index } = props;
    if (cx == null || cy == null || data[index] == null) return null;
    const prev = index > 0 ? data[index - 1][dataKey] : null;
    const next = index < data.length - 1 ? data[index + 1][dataKey] : null;
    if (prev != null || next != null) return null; // already part of a segment
    return <circle cx={cx} cy={cy} r={1.7} fill={color} stroke="none" />;
  };
}

// ── tooltip ────────────────────────────────────────────────────
function CapacityTooltip({ active, payload, lines, unit }) {
  if (!active || !payload || !payload.length) return null;
  const row = payload[0].payload;

  return (
    <div className="capacity-dash__tooltip">
      <div className="capacity-dash__tooltip-time">{formatFull(row.ms)} UTC</div>
      {lines.map((line) => {
        const value = row[line.key];
        return (
          <div className="capacity-dash__tooltip-row" key={line.key}>
            <span className="capacity-dash__tooltip-key">
              <span
                className="capacity-dash__swatch"
                style={{ backgroundColor: line.color }}
                aria-hidden="true"
              />
              {line.name}
            </span>
            <span className="capacity-dash__tooltip-value">
              {value == null ? "no sample" : formatValue(value, unit)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/**
 * The chart itself, shared by the interactive panes and the printed pages.
 *
 * Pass `width`/`height` to get a fixed-size chart (print); omit them for a
 * ResponsiveContainer (screen). Print charts also drop the syncId so they never
 * link their crosshair to the live panes.
 */
function ChartBody({ lines, data, rows, gaps, start, end, theme, height, width, unit }) {
  const chrome = CHART_CHROME[theme];
  const gapColor = GAP_COLOR[theme];
  const print = width != null;

  const chart = (
    <LineChart
      data={data}
      margin={CHART_MARGIN}
      syncId={print ? undefined : "capacity"}
      width={width}
      height={print ? height : undefined}
    >
      <CartesianGrid stroke={chrome.grid} strokeDasharray="0" vertical={false} />
      <XAxis
        dataKey="i"
        type="number"
        domain={[start, end]}
        allowDataOverflow
        tickFormatter={(i) => (rows[i] ? formatClock(rows[i].ms) : "")}
        minTickGap={40}
        stroke={chrome.axis}
        tick={{ fill: chrome.tick, fontSize: 10 }}
      />
      <YAxis
        width={Y_AXIS_WIDTH}
        domain={["auto", "auto"]}
        stroke={chrome.axis}
        tick={{ fill: chrome.tick, fontSize: 10 }}
        tickFormatter={formatTick}
      />
      {!print && (
        <Tooltip
          content={<CapacityTooltip lines={lines} unit={unit} />}
          cursor={{ stroke: chrome.cursor, strokeWidth: 1 }}
          isAnimationActive={false}
        />
      )}
      {gaps.map((gap) => (
        <ReferenceLine
          key={gap.at}
          x={gap.at}
          stroke={gapColor}
          strokeDasharray="4 3"
          strokeWidth={1.5}
          label={{
            value: `no data · ${formatDuration(gap.ms)}`,
            position: "insideTop",
            fill: gapColor,
            fontSize: 11,
            fontWeight: 600,
          }}
        />
      ))}
      {lines.map((line) => (
        <Line
          key={line.key}
          type={line.type}
          dataKey={line.key}
          name={line.name}
          stroke={line.color}
          strokeWidth={1.6}
          dot={makeDotRenderer(line.key, line.color, data)}
          activeDot={print ? false : { r: 2.6, strokeWidth: 0 }}
          isAnimationActive={false}
          connectNulls={false}
        />
      ))}
    </LineChart>
  );

  if (print) return chart;
  return (
    <ResponsiveContainer width="100%" height={height}>
      {chart}
    </ResponsiveContainer>
  );
}

/** Pane title + unit + toggleable legend, shared by screen and print. */
function PaneHeader({ pane, lines, hidden, onToggle }) {
  return (
    <header className="capacity-dash__pane-header">
      <div className="capacity-dash__pane-titles">
        <h2 className="capacity-dash__pane-title">{pane.title}</h2>
        <span className="capacity-dash__pane-unit">{pane.unit}</span>
      </div>
      <ul className="capacity-dash__legend">
        {lines.map((line) => {
          const off = hidden ? Boolean(hidden[line.key]) : false;
          const swatch = (
            <span
              className="capacity-dash__swatch"
              style={{ backgroundColor: line.color }}
              aria-hidden="true"
            />
          );
          return (
            <li key={line.key}>
              {onToggle ? (
                <button
                  type="button"
                  className={`capacity-dash__legend-item${
                    off ? " capacity-dash__legend-item--off" : ""
                  }`}
                  onClick={() => onToggle(line.key)}
                  aria-pressed={!off}
                >
                  {swatch}
                  {line.name}
                </button>
              ) : (
                <span className="capacity-dash__legend-item">
                  {swatch}
                  {line.name}
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </header>
  );
}

// ── one chart pane ─────────────────────────────────────────────
function ChartPane({ pane, rows, gaps, range, setRange, lastIndex, hidden, onToggle, loading, theme }) {
  const { containerRef, selection, handlers } = useZoomPan({ range, setRange, lastIndex });

  const [start, end] = range;
  // Slicing is what makes the Y axis rescale to the window instead of the whole run.
  const visible = useMemo(() => rows.slice(start, end + 1), [rows, start, end]);
  const visibleGaps = useMemo(
    () => gaps.filter((gap) => gap.at > start && gap.at < end),
    [gaps, start, end]
  );

  const painted = useMemo(() => paintLines(pane.lines, theme), [pane.lines, theme]);
  const shown = painted.filter((line) => !hidden[line.key]);

  return (
    <section className="capacity-dash__pane">
      <PaneHeader pane={pane} lines={painted} hidden={hidden} onToggle={onToggle} />

      <div
        className="capacity-dash__plot"
        ref={containerRef}
        {...handlers}
        role="presentation"
      >
        <ChartBody
          lines={shown}
          data={visible}
          rows={rows}
          gaps={visibleGaps}
          start={start}
          end={end}
          theme={theme}
          unit={pane.unit}
          height={215}
        />

        {selection && (
          <div
            className="capacity-dash__selection"
            style={{
              left: Math.min(selection.x0, selection.x1),
              width: Math.abs(selection.x1 - selection.x0),
            }}
          />
        )}
        {loading && <div className="capacity-dash__pane-veil" />}
      </div>
    </section>
  );
}

// ════════════════════════════════════════════════════════════════
//  Printable report — one chart per page, screen-hidden
// ════════════════════════════════════════════════════════════════
function PrintReport({ payload, rows, gaps, stats, periodText, theme }) {
  const summary = (payload && payload.summary) || {};
  const lastIndex = Math.max(0, rows.length - 1);

  return (
    <div className="capacity-dash__print" aria-hidden="true">
      {PANES.map((pane, index) => {
        const lines = paintLines(pane.lines, theme);
        return (
          <section className="capacity-dash__print-page" key={pane.id}>
            <header className="capacity-dash__print-head">
              <span className="capacity-dash__print-brand">Capacity report</span>
              <span className="capacity-dash__print-meta">
                {payload ? payload.agent_name : "—"} · {periodText} · UTC
              </span>
            </header>

            <h2 className="capacity-dash__print-h2">
              {index + 1}. {pane.title} <span>({pane.unit})</span>
            </h2>

            {/* the summary rides page 1 only */}
            {index === 0 && (
              <table className="capacity-dash__print-table">
                <tbody>
                  <tr>
                    {stats.map((stat) => (
                      <th key={stat.key}>{stat.label}</th>
                    ))}
                    <th>Samples</th>
                  </tr>
                  <tr>
                    {stats.map((stat) => (
                      <td key={stat.key}>
                        {summary[stat.key] == null ? "—" : Number(summary[stat.key]).toFixed(2)}{" "}
                        {stat.unit}
                      </td>
                    ))}
                    <td>{payload && payload.sample_count != null ? payload.sample_count : "—"}</td>
                  </tr>
                </tbody>
              </table>
            )}

            <PaneHeader pane={pane} lines={lines} />
            <ChartBody
              lines={lines}
              data={rows}
              rows={rows}
              gaps={gaps}
              start={0}
              end={lastIndex}
              theme={theme}
              unit={pane.unit}
              width={PRINT_W}
              height={PRINT_H}
            />

            <p className="capacity-dash__print-note">
              Full range, {rows.length} samples.
              {gaps.length
                ? ` ${gaps.length} reporting gap${gaps.length > 1 ? "s" : ""} marked on the chart.`
                : " No reporting gaps."}
            </p>
            <footer className="capacity-dash__print-foot">Page {index + 1} of {PANES.length}</footer>
          </section>
        );
      })}
    </div>
  );
}

// ── page ───────────────────────────────────────────────────────
export default function CapacityDashboard() {
  const initial = defaultLocalRange();

  const [agentName, setAgentName] = useState("UpdatedWindowAgent");
  const [fromLocal, setFromLocal] = useState(initial.from);
  const [toLocal, setToLocal] = useState(initial.to);

  const [payload, setPayload] = useState(null);
  const [status, setStatus] = useState("loading"); // loading | success | error
  const [error, setError] = useState(null);
  const [hidden, setHidden] = useState({});
  const [range, setRange] = useState([0, 0]);

  const [theme, setTheme] = useState(initialTheme);
  const [printing, setPrinting] = useState(false);

  const abortRef = useRef(null);
  const requestRef = useRef(0);
  const themeBeforePrint = useRef(theme);

  const rows = useMemo(() => buildRows(payload), [payload]);
  const gaps = useMemo(() => findGaps(rows), [rows]);
  const lastIndex = Math.max(0, rows.length - 1);

  // datetime-local gives "YYYY-MM-DDTHH:MM"; the API wants naive seconds.
  const toParams = useCallback(
    () => ({ agentName: agentName.trim(), fromDt: `${fromLocal}:00`, toDt: `${toLocal}:59` }),
    [agentName, fromLocal, toLocal]
  );

  const load = useCallback(
    async (params) => {
      if (!params.agentName) {
        setError({ message: "Enter an agent name to load.", status: 0, url: "" });
        setStatus("error");
        return;
      }
      if (params.fromDt >= params.toDt) {
        setError({ message: "From must be earlier than To.", status: 0, url: "" });
        setStatus("error");
        return;
      }

      if (abortRef.current) abortRef.current.abort();
      const controller = new AbortController();
      abortRef.current = controller;
      const ticket = ++requestRef.current;

      setStatus("loading");
      setError(null);

      try {
        const data = await fetchOverview(params, { signal: controller.signal });
        if (ticket !== requestRef.current) return; // a newer load won
        setPayload(data);
        setStatus("success");
      } catch (err) {
        if (err && (err.code === "ERR_CANCELED" || err.name === "CanceledError")) return;
        if (ticket !== requestRef.current) return;
        // The last good payload stays in state, so the charts stay on screen.
        setError({
          message: err.message,
          status: err.status || 0,
          url: err.url || absoluteOverviewUrl(params),
        });
        setStatus("error");
      }
    },
    []
  );

  // Reset the window whenever the underlying run changes size.
  useEffect(() => {
    setRange([0, Math.max(0, rows.length - 1)]);
  }, [rows.length]);

  useEffect(() => {
    load(toParams());
    return () => {
      if (abortRef.current) abortRef.current.abort();
    };
    // Load once on mount; every later load is driven by the Load button.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // persist the theme choice
  useEffect(() => {
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch (_) {
      /* storage blocked — the choice just will not survive a reload */
    }
  }, [theme]);

  /**
   * Export to PDF via the browser's own print-to-PDF, so there is no PDF
   * dependency to ship. The print tree only mounts while `printing` is true —
   * mounting it always would render four extra 283-point charts on every load.
   * The dialog is opened one frame after the commit so the charts are in the DOM
   * and laid out before the browser snapshots the page.
   */
  useEffect(() => {
    if (!printing) return undefined;

    let raf2 = 0;
    const raf1 = window.requestAnimationFrame(() => {
      raf2 = window.requestAnimationFrame(() => {
        try {
          window.print();
        } finally {
          setPrinting(false);
          setTheme(themeBeforePrint.current);
        }
      });
    });
    return () => {
      window.cancelAnimationFrame(raf1);
      if (raf2) window.cancelAnimationFrame(raf2);
    };
  }, [printing]);

  const exportPdf = () => {
    if (!rows.length || printing) return;
    // Paper is white: print the light palette whatever the screen is showing,
    // then put the user's theme back.
    themeBeforePrint.current = theme;
    setTheme("light");
    setPrinting(true);
  };

  const onSubmit = (event) => {
    event.preventDefault();
    load(toParams());
  };

  const widenTo24h = () => {
    const next = defaultLocalRange();
    setFromLocal(next.from);
    setToLocal(next.to);
    load({ agentName: agentName.trim(), fromDt: `${next.from}:00`, toDt: `${next.to}:59` });
  };

  const toggle = (key) => setHidden((h) => ({ ...h, [key]: !h[key] }));

  const zoomBy = (factor) => {
    const [start, end] = range;
    const centre = (start + end) / 2;
    setRange(clampRange(centre - (centre - start) * factor, centre + (end - centre) * factor, lastIndex));
  };
  const showLast = (n) => setRange(clampRange(lastIndex - n, lastIndex, lastIndex));

  const loading = status === "loading";
  const summary = (payload && payload.summary) || {};
  const isEmpty = status !== "loading" && payload != null && rows.length === 0;

  const periodText = `${fromLocal.replace("T", " ")} – ${toLocal.replace("T", " ")}`;

  return (
    <div className={`capacity-dash capacity-dash--${theme}`}>
      <header className="capacity-dash__topbar">
        <div className="capacity-dash__brand">
          <h1 className="capacity-dash__title">Capacity monitoring</h1>
          <p className="capacity-dash__subtitle">
            {payload ? `${payload.agent_name} · ${rows.length} samples · times in UTC` : "times in UTC"}
          </p>
        </div>

        <form className="capacity-dash__controls" onSubmit={onSubmit}>
          <label className="capacity-dash__field">
            <span className="capacity-dash__field-label">Agent name</span>
            <input
              className="capacity-dash__input"
              type="text"
              value={agentName}
              onChange={(e) => setAgentName(e.target.value)}
              placeholder="Please enter an agent name"
              autoComplete="off"
            />
          </label>
          <label className="capacity-dash__field">
            <span className="capacity-dash__field-label">From</span>
            <input
              className="capacity-dash__input"
              type="datetime-local"
              value={fromLocal}
              max={toLocal}
              onChange={(e) => setFromLocal(e.target.value)}
            />
          </label>
          <label className="capacity-dash__field">
            <span className="capacity-dash__field-label">To</span>
            <input
              className="capacity-dash__input"
              type="datetime-local"
              value={toLocal}
              min={fromLocal}
              onChange={(e) => setToLocal(e.target.value)}
            />
          </label>
          <button
            className="capacity-dash__btn capacity-dash__btn--primary"
            type="submit"
            disabled={loading}
          >
            {loading ? "Loading…" : "Load"}
          </button>

          <button
            className="capacity-dash__btn"
            type="button"
            onClick={exportPdf}
            disabled={!rows.length || printing}
            title={rows.length ? "Open the print dialog — choose Save as PDF" : "Load data first"}
          >
            {printing ? "Preparing…" : "Export PDF"}
          </button>

          <button
            className="capacity-dash__btn capacity-dash__btn--icon"
            type="button"
            onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
            aria-pressed={theme === "light"}
            title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          >
            <span aria-hidden="true">{theme === "dark" ? "☀" : "☾"}</span>
            <span className="capacity-dash__sr-only">
              {theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            </span>
          </button>
        </form>
      </header>

      {status === "error" && error && (
        <div className="capacity-dash__error" role="alert">
          <div className="capacity-dash__error-body">
            <p className="capacity-dash__error-msg">
              {error.status ? `HTTP ${error.status} — ` : ""}
              {error.message}
            </p>
            {error.url && <code className="capacity-dash__error-url">{error.url}</code>}
            {payload && <p className="capacity-dash__error-note">Showing the last window that loaded.</p>}
          </div>
          <button
            className="capacity-dash__btn"
            type="button"
            onClick={() => load(toParams())}
            disabled={loading}
          >
            Retry
          </button>
        </div>
      )}

      <div className={`capacity-dash__stats${loading ? " capacity-dash__stats--loading" : ""}`}>
        {STATS.map((stat) => {
          const value = summary[stat.key];
          return (
            <div
              className={`capacity-dash__stat capacity-dash__stat--${stat.modifier}`}
              key={stat.key}
            >
              <span className="capacity-dash__stat-label">{stat.label}</span>
              <span className="capacity-dash__stat-value">
                {value == null ? "—" : Number(value).toFixed(2)}
                <span className="capacity-dash__stat-unit">{stat.unit}</span>
              </span>
            </div>
          );
        })}
        <div className="capacity-dash__stat capacity-dash__stat--samples">
          <span className="capacity-dash__stat-label">Samples</span>
          <span className="capacity-dash__stat-value">
            {payload && payload.sample_count != null ? payload.sample_count : "—"}
            <span className="capacity-dash__stat-unit">pts</span>
          </span>
        </div>
      </div>

      {isEmpty ? (
        <div className="capacity-dash__empty">
          <p className="capacity-dash__empty-title">No samples in this window</p>
          <p className="capacity-dash__empty-sub">
            The agent reported nothing between {fromLocal.replace("T", " ")} and{" "}
            {toLocal.replace("T", " ")}.
          </p>
          <button className="capacity-dash__btn" type="button" onClick={widenTo24h}>
            Widen to last 24h
          </button>
        </div>
      ) : (
        <>
          <div className="capacity-dash__toolbar">
            <span className="capacity-dash__toolbar-label">
              {rows.length
                ? `${formatClock(rows[range[0]] && rows[range[0]].ms)} – ${formatClock(
                    rows[range[1]] && rows[range[1]].ms
                  )} · ${range[1] - range[0] + 1} pts`
                : "—"}
            </span>
            <div className="capacity-dash__toolbar-actions">
              <button className="capacity-dash__btn" type="button" onClick={() => zoomBy(ZOOM_IN)}>
                Zoom in
              </button>
              <button className="capacity-dash__btn" type="button" onClick={() => zoomBy(ZOOM_OUT)}>
                Zoom out
              </button>
              <button className="capacity-dash__btn" type="button" onClick={() => showLast(30)}>
                Last 30
              </button>
              <button className="capacity-dash__btn" type="button" onClick={() => showLast(100)}>
                Last 100
              </button>
              <button
                className="capacity-dash__btn"
                type="button"
                onClick={() => setRange([0, lastIndex])}
              >
                All
              </button>
            </div>
            <span className="capacity-dash__hint">
              Wheel to zoom · drag to pan · shift-drag to box zoom · double-click to reset
            </span>
          </div>

          <div className="capacity-dash__panes">
            {PANES.map((pane) => (
              <ChartPane
                key={pane.id}
                pane={pane}
                rows={rows}
                gaps={gaps}
                range={range}
                setRange={setRange}
                lastIndex={lastIndex}
                hidden={hidden}
                onToggle={toggle}
                loading={loading}
                theme={theme}
              />
            ))}
          </div>

          <section className="capacity-dash__overview">
            <header className="capacity-dash__pane-header">
              <div className="capacity-dash__pane-titles">
                <h2 className="capacity-dash__pane-title">Full range</h2>
                <span className="capacity-dash__pane-unit">host CPU %</span>
              </div>
            </header>
            <ResponsiveContainer width="100%" height={92}>
              <AreaChart data={rows} margin={{ top: 4, right: 14, bottom: 0, left: 4 }}>
                <YAxis hide domain={["auto", "auto"]} />
                <XAxis dataKey="i" type="number" domain={[0, lastIndex]} hide />
                <Area
                  type="monotone"
                  dataKey="cpu"
                  stroke={SERIES_COLORS[theme].cpu}
                  fill={SERIES_COLORS[theme].cpu}
                  fillOpacity={0.14}
                  strokeWidth={1.2}
                  dot={false}
                  isAnimationActive={false}
                  connectNulls={false}
                />
                {rows.length > 1 && (
                  <Brush
                    dataKey="i"
                    height={22}
                    travellerWidth={8}
                    stroke={CHART_CHROME[theme].cursor}
                    fill="transparent"
                    startIndex={range[0]}
                    endIndex={range[1]}
                    onChange={(next) => {
                      if (!next || next.startIndex == null || next.endIndex == null) return;
                      if (next.startIndex === range[0] && next.endIndex === range[1]) return;
                      setRange(clampRange(next.startIndex, next.endIndex, lastIndex));
                    }}
                    tickFormatter={(i) => (rows[i] ? formatClock(rows[i].ms) : "")}
                  />
                )}
              </AreaChart>
            </ResponsiveContainer>
          </section>
        </>
      )}

      {printing && (
        <PrintReport
          payload={payload}
          rows={rows}
          gaps={gaps}
          stats={STATS}
          periodText={periodText}
          theme={theme}
        />
      )}
    </div>
  );
}
