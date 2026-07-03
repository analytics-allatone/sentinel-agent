import React, { useState } from "react";
import "./AgentCardGrid.css";

// ─── Static data ──────────────────────────────────────────────
const CARDS = [
  {
    key: "auth",
    label: "Auth",
    icon: "🔐",
    total: "3,241",
    statusText: "48 failed",
    statusTone: "warn",
    accent: "auth",
    miniLabel: "Auth logs",
    deltaVal: "+12%",
    deltaDir: "up",
    deltaText: "vs yesterday",
    bars: [30, 45, 38, 52, 42, 48, 40, 88, 44, 50, 42, 92],
  },
  {
    key: "network",
    label: "Network",
    icon: "🌐",
    total: "9,104",
    statusText: "12 blocked",
    statusTone: "warn",
    accent: "network",
    miniLabel: "Network",
    deltaVal: "-3%",
    deltaDir: "down",
    deltaText: "vs yesterday",
    bars: [60, 55, 62, 58, 70, 55, 65, 92, 58, 66, 60, 96],
  },
  {
    key: "process",
    label: "Process",
    icon: "⚙️",
    total: "2,487",
    statusText: "healthy",
    statusTone: "ok",
    accent: "process",
    miniLabel: "Process",
    deltaVal: "0%",
    deltaDir: "flat",
    deltaText: "no change",
    bars: [62, 64, 60, 65, 62, 63, 61, 95, 63, 64, 62, 98],
  },
  {
    key: "file",
    label: "File",
    icon: "📁",
    total: "1,203",
    statusText: "2 modified",
    statusTone: "warn",
    accent: "file",
    miniLabel: "File events",
    deltaVal: "+5%",
    deltaDir: "up",
    deltaText: "vs yesterday",
    bars: [35, 40, 36, 44, 38, 42, 37, 85, 40, 44, 38, 90],
  },
];

const ACCENT = {
  auth: { light: "#EBF1FB", mid: "#93B4E8", dark: "#2255A4", text: "#1A3D7C" },
  network: {
    light: "#E6F5EE",
    mid: "#80CEAD",
    dark: "#1B7A52",
    text: "#155C3D",
  },
  process: {
    light: "#FEF4E3",
    mid: "#F0C570",
    dark: "#A07020",
    text: "#7A5217",
  },
  file: { light: "#FCEDF3", mid: "#EBA8C4", dark: "#8C2050", text: "#6B1840" },
};

// ─── Sub‑components ──────────────────────────────────────────

function TrendArrow({ dir }) {
  if (dir === "up") return <span className="arrow up">▲</span>;
  if (dir === "down") return <span className="arrow down">▼</span>;
  return <span className="arrow flat">—</span>;
}

function Sparkline({ bars, accent }) {
  const colors = ACCENT[accent];
  return (
    <div className="sparkline">
      {bars.map((h, i) => {
        const isHighlight = i >= bars.length - 2;
        return (
          <div
            key={i}
            className="sparkline-bar"
            style={{
              height: `${h}%`,
              background: isHighlight ? colors.dark : colors.mid,
              opacity: isHighlight ? 1 : 0.7,
            }}
          />
        );
      })}
    </div>
  );
}

function Card({ card }) {
  const [hovered, setHovered] = useState(false);
  const colors = ACCENT[card.accent];

  return (
    <div
      className={`card ${hovered ? "card-hovered" : ""}`}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        "--accent-light": colors.light,
        "--accent-dark": colors.dark,
        "--accent-text": colors.text,
      }}
    >
      <div className="card-strip" style={{ background: colors.dark }} />
      <div className="card-body">
        <div className="card-header-row">
          <div className="card-icon-label">
            <span className="card-icon">{card.icon}</span>
            <span className="card-label">{card.label}</span>
          </div>
          <span className={`status-pill status-${card.statusTone}`}>
            {card.statusText}
          </span>
        </div>

        <div className="card-total" style={{ color: colors.text }}>
          {card.total}
        </div>

        <div className="card-mini-row">
          <span
            className="mini-swatch"
            style={{
              background: colors.light,
              border: `1.5px solid ${colors.mid}`,
            }}
          />
          <span className="mini-label">{card.miniLabel}</span>
        </div>

        <div className="card-divider" style={{ background: colors.light }} />

        <div className="trend-row">
          <TrendArrow dir={card.deltaDir} />
          <span className={`delta-val delta-${card.deltaDir}`}>
            {card.deltaVal}
          </span>
          <span className="delta-text">{card.deltaText}</span>
        </div>

        <Sparkline bars={card.bars} accent={card.accent} />
      </div>
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────

export default function AgentCardGrid() {
  const [cards, setCards] = useState(CARDS);
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [loading, setLoading] = useState(false);
  const [filterActive, setFilterActive] = useState(false);

  const totalEvents = cards
    .reduce((sum, c) => sum + parseInt(c.total.replace(/,/g, "")), 0)
    .toLocaleString();

  // ── API call (replace with your real endpoint) ──────────────
  const fetchFilteredData = async (from, to) => {
    setLoading(true);
    const params = new URLSearchParams();
    if (from) params.append("from", from);
    if (to) params.append("to", to);

    // 👇 Replace this with your actual API call
    // const response = await fetch(`/api/events?${params.toString()}`);
    // const data = await response.json();
    // setCards(data.cards);

    // ─── Simulation (remove in production) ──────────────────────
    await new Promise((resolve) => setTimeout(resolve, 700));
    const filtered = CARDS.map((c) => {
      const base = parseInt(c.total.replace(/,/g, ""));
      const factor = 0.85 + Math.random() * 0.3;
      const newTotal = Math.round(base * factor);
      const formatted = newTotal.toLocaleString();

      let statusText = c.statusText;
      if (c.statusTone === "warn") {
        const num = Math.floor(Math.random() * 60) + 10;
        statusText =
          c.key === "auth"
            ? `${num} failed`
            : c.key === "network"
              ? `${num} blocked`
              : `${num} modified`;
      }

      const deltaNum = parseFloat((Math.random() * 20 - 5).toFixed(1));
      const deltaDir =
        deltaNum > 0.5 ? "up" : deltaNum < -0.5 ? "down" : "flat";
      const deltaText =
        deltaNum > 0.5
          ? "vs filtered"
          : deltaNum < -0.5
            ? "vs filtered"
            : "no change";

      const bars = c.bars.map((b) => {
        const shift = Math.floor(Math.random() * 10 - 5);
        return Math.min(100, Math.max(10, b + shift));
      });

      return {
        ...c,
        total: formatted,
        statusText,
        deltaVal: `${deltaNum > 0 ? "+" : ""}${deltaNum}%`,
        deltaDir,
        deltaText,
        bars,
      };
    });
    setCards(filtered);
    setFilterActive(!!from || !!to);
    // ─── End simulation ──────────────────────────────────────────

    setLoading(false);
  };

  const handleApplyFilter = () => {
    if (fromDate && toDate && fromDate > toDate) {
      alert("⚠️ 'From' date must be before 'To' date.");
      return;
    }
    fetchFilteredData(fromDate, toDate);
  };

  const handleClearFilter = () => {
    setFromDate("");
    setToDate("");
    setFilterActive(false);
    setCards(CARDS);
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleApplyFilter();
    }
  };

  return (
    <div className="dashboard">
      {/* Page header */}
      {/* <div className="page-header">
        <h1 className="page-title">
          Card grid overview <span className="arrow-sep">→</span> drill-down
        </h1>
        <p className="page-sub">
          Overview page shows one card per log category with a mini sparkline.
          Use the date filter below to narrow down events by time range.
        </p>
      </div> */}

      {/* Filter Bar */}
      <div className="filter-bar">
        <div className="filter-group">
          <label htmlFor="fromDate">From</label>
          <input
            type="datetime-local"
            id="fromDate"
            value={fromDate}
            onChange={(e) => setFromDate(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading}
          />
        </div>

        <div className="filter-group">
          <label htmlFor="toDate">To</label>
          <input
            type="datetime-local"
            id="toDate"
            value={toDate}
            onChange={(e) => setToDate(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading}
          />
        </div>

        <div className="filter-actions">
          <button
            className="btn-filter btn-apply"
            onClick={handleApplyFilter}
            disabled={loading}
          >
            {loading ? <span className="spinner-small" /> : "Apply 🚀"}
          </button>
          <button
            className="btn-filter btn-clear"
            onClick={handleClearFilter}
            disabled={loading}
          >
            Clear
          </button>
          <span className="filter-status">
            <span className={`dot ${filterActive ? "active" : "inactive"}`} />
            {filterActive ? "Filtered" : "All data"}
          </span>
        </div>
      </div>

      {/* Section Bar */}
      <div className="section-bar">
        <div className="section-left">
          <span className="sentinel-dot" />
          <span className="section-title">Sentinel</span>
          <span className="section-em">— overview</span>
        </div>
        <div className="section-right">
          <span className="total-events-label">Total events</span>
          <span className="total-events-val">{totalEvents}</span>
          <span className="critical-badge">
            <span className="critical-dot" />3 critical
          </span>
        </div>
      </div>

      {/* Card Grid */}
      <div className="card-grid">
        {cards.map((card) => (
          <Card key={card.key} card={card} />
        ))}
      </div>
    </div>
  );
}
