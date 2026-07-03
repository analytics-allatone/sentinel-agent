import { useState, useRef, useEffect } from "react";
import "./AgentDetails.css";

// ─── SVG Gauge ──────────────────────────────────────────────────────────────
function Gauge({
  value,
  max,
  label,
  gradientId,
  colors,
  size = 140,
  cardWidth = 240,
}) {
  const r = 80;
  const cx = size / 2;
  const cy = size / 2 + 8;
  const startAngle = -130;
  const endAngle = 130;
  const totalAngle = endAngle - startAngle;
  const pct = Math.min(1, Math.max(0, value / max));
  const fillAngle = totalAngle * pct;

  function polarToXY(angle, radius) {
    const rad = ((angle - 90) * Math.PI) / 180;
    return { x: cx + radius * Math.cos(rad), y: cy + radius * Math.sin(rad) };
  }

  function arc(startAng, endAng, r) {
    const s = polarToXY(startAng, r);
    const e = polarToXY(endAng, r);
    const large = endAng - startAng > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`;
  }

  return (
    <div className="gauge-container" style={{ width: cardWidth, height: size }}>
      <svg className="gauge-svg" viewBox={`0 0 ${size} ${size}`}>
        <defs>
          <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="0%">
            {colors.map((c, i) => (
              <stop
                key={i}
                offset={`${(i / (colors.length - 1)) * 100}%`}
                stopColor={c}
              />
            ))}
          </linearGradient>
        </defs>
        {/* Track */}
        <path
          d={arc(startAngle, endAngle, r)}
          fill="none"
          stroke="var(--gauge-track)"
          strokeWidth="10"
          strokeLinecap="round"
        />
        {/* Fill */}
        {pct > 0 && (
          <path
            d={arc(startAngle, startAngle + fillAngle, r)}
            fill="none"
            stroke={`url(#${gradientId})`}
            strokeWidth="10"
            strokeLinecap="round"
          />
        )}
      </svg>
      <div className="gauge-text">
        <span className="gauge-value">{value.toLocaleString()}</span>
        <span className="gauge-sublabel">{label}</span>
      </div>
    </div>
  );
}

// ─── Bar Chart for Actions ────────────────────────────────────────────────────
function ActionBar({ count, label, barClass, heightPx }) {
  return (
    <div className="action-col">
      <span className="action-count">{count}</span>
      <div className="action-bar-wrap">
        <div
          className={`action-bar ${barClass}`}
          style={{ height: heightPx }}
        />
      </div>
      <span className="action-label">{label}</span>
    </div>
  );
}

// ─── Timeline Placeholder ─────────────────────────────────────────────────────
function Timeline() {
  const xLabels = [
    "09:00",
    "09:30",
    "10:00",
    "10:30",
    "11:00",
    "11:30",
    "12:00",
    "12:30",
    "13:00",
    "13:30",
    "14:00",
    "14:30",
  ];
  const yLabels = ["500", "400", "300", "200", "100", "0"];
  const legendItems = [
    "id",
    "agent_id",
    "file_size_bytes",
    "user_uid",
    "user_gid",
    "user_effective_uid",
    "user_effective_gid",
    "risk_score",
  ];

  return (
    <div className="timeline-chart-area">
      <div style={{ display: "flex", flex: 1, minHeight: 160 }}>
        <div className="timeline-yaxis">
          {yLabels.map((l) => (
            <span key={l}>{l}</span>
          ))}
        </div>
        <div className="timeline-grid" style={{ flex: 1 }}>
          <div className="timeline-grid-lines">
            {yLabels.map((l) => (
              <div key={l} className="grid-line" />
            ))}
          </div>
          <div className="timeline-no-data">
            <div className="no-data-text">Data outside time range</div>
            {/* <button className="zoom-btn">Zoom to data</button> */}
          </div>
          {/* Right axis True/False */}
          {/* <div className="right-axis">
            <span>True</span>
            <span>False</span>
          </div> */}
        </div>
      </div>
      <div className="timeline-xaxis">
        {xLabels.map((l) => (
          <span key={l}>{l}</span>
        ))}
      </div>
      <div className="timeline-legend">
        {legendItems.map((item) => (
          <div key={item} className="legend-item">
            <div className="legend-line" />
            <span>{item}</span>
          </div>
        ))}
        <div className="legend-item">
          <div className="legend-line anomaly" />
          <span>anomaly</span>
        </div>
      </div>
    </div>
  );
}

// ─── Date/Time Range Filter ───────────────────────────────────────────────────
const RANGE_PRESETS = [
  { key: "15m", label: "Last 15 minutes", ms: 15 * 60 * 1000 },
  { key: "1h", label: "Last 1 hour", ms: 60 * 60 * 1000 },
  { key: "6h", label: "Last 6 hours", ms: 6 * 60 * 60 * 1000 },
  { key: "24h", label: "Last 24 hours", ms: 24 * 60 * 60 * 1000 },
  { key: "2d", label: "Last 2 days", ms: 2 * 24 * 60 * 60 * 1000 },
  { key: "7d", label: "Last 7 days", ms: 7 * 24 * 60 * 60 * 1000 },
  { key: "30d", label: "Last 30 days", ms: 30 * 24 * 60 * 60 * 1000 },
  { key: "90d", label: "Last 90 days", ms: 90 * 24 * 60 * 60 * 1000 },
];

function toLocalInputValue(date) {
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate(),
  )}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function TimeRangeFilter({ range, onChange }) {
  const [open, setOpen] = useState(false);
  const [customFrom, setCustomFrom] = useState(toLocalInputValue(range.from));
  const [customTo, setCustomTo] = useState(toLocalInputValue(range.to));
  const wrapRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(e) {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    setCustomFrom(toLocalInputValue(range.from));
    setCustomTo(toLocalInputValue(range.to));
  }, [range]);

  function applyPreset(preset) {
    const to = new Date();
    const from = new Date(to.getTime() - preset.ms);
    onChange({ key: preset.key, label: preset.label, from, to });
    setOpen(false);
  }

  function applyCustom() {
    const from = new Date(customFrom);
    const to = new Date(customTo);
    if (isNaN(from) || isNaN(to) || from >= to) return;
    onChange({
      key: "custom",
      label: "Custom range",
      from,
      to,
    });
    setOpen(false);
  }

  function shift(direction) {
    const span = range.to.getTime() - range.from.getTime();
    const delta = span * direction;
    const from = new Date(range.from.getTime() + delta);
    const to = new Date(range.to.getTime() + delta);
    onChange({ ...range, key: "custom", label: "Custom range", from, to });
  }

  return (
    <div className="time-range-wrap" ref={wrapRef}>
      <div className="time-controls">
        <button
          className="time-btn"
          title="Shift back"
          onClick={() => shift(-1)}
        >
          «
        </button>
        <button
          className="time-btn range-btn"
          onClick={() => setOpen((o) => !o)}
        >
          <span className="range-btn-icon">🕐</span>
          {range.label}
          <span className="range-btn-caret">▾</span>
        </button>
        <button
          className="time-btn"
          title="Shift forward"
          onClick={() => shift(1)}
        >
          »
        </button>
        <button
          className="time-btn"
          title="Refresh"
          onClick={() => onChange({ ...range })}
        >
          ⊖
        </button>
      </div>

      {open && (
        <div className="time-range-popover">
          <div className="time-range-popover-inner">
            <div className="time-range-quick">
              <div className="time-range-quick-title">Quick ranges</div>
              <ul>
                {RANGE_PRESETS.map((p) => (
                  <li key={p.key}>
                    <button
                      className={`quick-range-item${
                        range.key === p.key ? " active" : ""
                      }`}
                      onClick={() => applyPreset(p)}
                    >
                      {p.label}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
            <div className="time-range-custom">
              <div className="time-range-quick-title">Custom range</div>
              <label className="custom-range-field">
                <span>From</span>
                <input
                  type="datetime-local"
                  value={customFrom}
                  onChange={(e) => setCustomFrom(e.target.value)}
                />
              </label>
              <label className="custom-range-field">
                <span>To</span>
                <input
                  type="datetime-local"
                  value={customTo}
                  onChange={(e) => setCustomTo(e.target.value)}
                />
              </label>
              <button className="apply-range-btn" onClick={applyCustom}>
                Apply time range
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Data Table ───────────────────────────────────────────────────────────────
function DataTable({ rows, page, setPage, totalRows }) {
  const ROWS_PER_PAGE = 6;
  const totalPages = Math.ceil(totalRows / ROWS_PER_PAGE);
  const visibleRows = rows.slice(
    (page - 1) * ROWS_PER_PAGE,
    page * ROWS_PER_PAGE,
  );

  const columns = [
    { key: "agent_id", label: "agent_id" },
    { key: "file_path", label: "file_path" },
    { key: "file_created_at", label: "file_created_at" },
    { key: "severity", label: "severity" },
    { key: "anomaly", label: "anomaly" },
    { key: "file_size_bytes", label: "file_size_bytes" },
    { key: "file_owner", label: "file_owner" },
  ];

  // Build page numbers to display
  const pageNums = [];
  if (totalPages <= 7) {
    for (let i = 1; i <= totalPages; i++) pageNums.push(i);
  } else {
    pageNums.push(1, 2, 3, 4, 5, 6, 7, "...", totalPages);
  }

  return (
    <div className="table-card-0">
      <div style={{ overflowX: "auto" }}>
        <table className="data-table">
          <thead>
            <tr>
              {columns.map((col) => (
                <th key={col.key}>
                  <div className="col-head">
                    {col.label}
                    <span className="filter-icon">▽</span>
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visibleRows.map((row, i) => (
              <tr key={i}>
                <td>{row.agent_id}</td>
                <td title={row.file_path}>{row.file_path}</td>
                <td>{row.file_created_at || ""}</td>
                <td>
                  <span className="severity-badge">{row.severity}</span>
                </td>
                <td>
                  <span className="anomaly-badge">{row.anomaly}</span>
                </td>
                <td>{row.file_size_bytes ?? ""}</td>
                <td>{row.file_owner || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pagination-bar">
        <button
          className="page-btn nav"
          onClick={() => setPage(1)}
          disabled={page === 1}
        >
          «
        </button>
        <button
          className="page-btn nav"
          onClick={() => setPage(Math.max(1, page - 1))}
          disabled={page === 1}
        >
          ‹
        </button>
        {pageNums.map((p, i) =>
          p === "..." ? (
            <span
              key={i}
              style={{ padding: "0 4px", color: "var(--text-muted)" }}
            >
              …
            </span>
          ) : (
            <button
              key={p}
              className={`page-btn${page === p ? " active" : ""}`}
              onClick={() => setPage(p)}
            >
              {p}
            </button>
          ),
        )}
        <button
          className="page-btn nav"
          onClick={() => setPage(Math.min(totalPages, page + 1))}
          disabled={page === totalPages}
        >
          ›
        </button>
        <span className="page-info">
          {(page - 1) * ROWS_PER_PAGE + 1} –{" "}
          {Math.min(page * ROWS_PER_PAGE, totalRows)} of {totalRows} rows
        </span>
      </div>
    </div>
  );
}

// ─── Sample Data Generator ───────────────────────────────────────────────────
function generateRows(agentId, count) {
  const severities = ["info", "info", "info", "critical"];
  const paths = [
    "C:\\Users\\Admin\\AppData\\Local\\Temp\\tmp_file.dat",
    "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\config.json",
    "C:\\Users\\Admin\\AppData\\Local\\log.txt",
    "C:\\Users\\Admin\\AppData\\Local\\cache\\data.bin",
    "C:\\Users\\Admin\\Documents\\report.pdf",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
  ];
  const timestamps = [
    "2026-05-26 19:55:16",
    "2026-05-26 19:55:16",
    "",
    "",
    "2026-05-26 19:55:17",
    "",
  ];
  const sizes = [0, 0, undefined, undefined, 64989, undefined];
  const rows = [];
  for (let i = 0; i < count; i++) {
    const idx = i % 6;
    rows.push({
      agent_id: agentId,
      file_path: paths[idx],
      file_created_at: timestamps[idx],
      severity: severities[i % 4 === 3 ? 3 : 0],
      anomaly: "false",
      file_size_bytes: sizes[idx],
      file_owner: "",
    });
  }
  return rows;
}

// ─── Agent Dashboard (Main) ──────────────────────────────────────────────────
export default function AgentDetails({ agentData }) {
  const [darkMode, setDarkMode] = useState(true);
  const [page, setPage] = useState(1);
  const [agentFilter, setAgentFilter] = useState(
    agentData?.agentName ?? "TestAgent",
  );

  // Default time range: last 7 days
  const [timeRange, setTimeRange] = useState(() => {
    const preset = RANGE_PRESETS.find((p) => p.key === "7d");
    const to = new Date();
    const from = new Date(to.getTime() - preset.ms);
    return { key: preset.key, label: preset.label, from, to };
  });

  // Default data if none provided
  const data = agentData ?? {
    agentName: "TestAgent",
    outcome: { success: 1830, total: 1830 },
    severity: { critical: 250, info: 1580 },
    actions: { create: 290, delete: 260, rename: 134, update: 1146 },
    totalRows: 1830,
  };

  const rows = generateRows(1, data.totalRows);

  // Bar heights scaled to max action
  const maxAction = Math.max(
    data.actions.create,
    data.actions.delete,
    data.actions.rename,
    data.actions.update,
  );
  function barHeight(val) {
    return Math.max(8, Math.round((val / maxAction) * 140));
  }

  return (
    <div className={`dashboard-root${darkMode ? "" : " light-mode"}`}>
      {/* TOP BAR */}

      {/* FILTER BAR */}
      <div className="filter-bar">
        <span className="filter-label">Agent Name</span>

        <div className="filter-sep" />

        <TimeRangeFilter range={timeRange} onChange={setTimeRange} />

        <button
          className="theme-toggle"
          onClick={() => setDarkMode((d) => !d)}
          title="Toggle dark/light mode"
        >
          {darkMode ? "☀ Light" : "🌙 Dark"}
        </button>
      </div>

      {/* MAIN DASHBOARD */}
      <div className="dashboard-main">
        {/* FILE Section label */}
        {/* <div className="section-collapse">
          <span className="arrow">▾</span> File
        </div> */}

        {/* TOP ROW */}
        <div className="top-row">
          {/* OUTCOME */}
          <div className="card-0 outcome-card-0">
            <div className="card-0-title">Outcome</div>
            <div className="gauge-wrap">
              <Gauge
                value={data.outcome.success}
                max={data.outcome.total}
                label="success"
                gradientId="outcome-grad"
                colors={["#7b2d8b", "#e040fb", "#fa4d56"]}
                size={260}
              />
            </div>
          </div>

          {/* SEVERITY */}
          <div className="card-0 severity-card-0">
            <div className="card-0-title">Severity</div>
            <div className="severity-gauges">
              <div className="severity-item">
                <Gauge
                  value={data.severity.critical}
                  max={data.outcome.total}
                  label="critical"
                  gradientId="crit-grad"
                  colors={["#5f1fa0", "#b044e0", "#e06030", "#fa8231"]}
                  size={260}
                />
              </div>
              <div className="severity-item">
                <Gauge
                  value={data.severity.critical}
                  max={data.outcome.total}
                  label="critical"
                  gradientId="crit-grad"
                  colors={["#5f1fa0", "#b044e0", "#e06030", "#fa8231"]}
                  size={260}
                />
              </div>
              <div className="severity-item">
                <Gauge
                  value={data.severity.info}
                  max={data.outcome.total}
                  label="info"
                  gradientId="info-grad"
                  colors={["#5f1fa0", "#b044e0", "#e06030", "#fa8231"]}
                  size={260}
                />
              </div>
            </div>
          </div>
        </div>

        {/* BOTTOM ROW */}
        <div className="bottom-row">
          {/* ACTIONS */}
          <div className="card-0">
            <div className="card-0-title">Actions</div>
            <div className="actions-bars">
              <ActionBar
                count={data.actions.create}
                label="create"
                barClass="bar-create"
                heightPx={barHeight(data.actions.create)}
              />
              <ActionBar
                count={data.actions.delete}
                label="delete"
                barClass="bar-delete"
                heightPx={barHeight(data.actions.delete)}
              />
              <ActionBar
                count={data.actions.rename}
                label="rename"
                barClass="bar-rename"
                heightPx={barHeight(data.actions.rename)}
              />
              <ActionBar
                count={data.actions.update}
                label="update"
                barClass="bar-update"
                heightPx={barHeight(data.actions.update)}
              />
            </div>
          </div>

          {/* TIMELINE */}
          <div className="card-0 timeline-card-0">
            <div className="card-0-title">Agent Ingested Time Stamp</div>
            <Timeline />
          </div>
        </div>

        {/* DATA TABLE */}
        <DataTable
          rows={rows}
          page={page}
          setPage={setPage}
          totalRows={data.totalRows}
        />
      </div>
    </div>
  );
}
