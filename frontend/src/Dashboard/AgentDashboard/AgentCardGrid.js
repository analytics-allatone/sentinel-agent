import React, { useState } from "react";
import "./AgentCardGrid.css";

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
      {/* Top accent strip */}
      <div className="card-strip" style={{ background: colors.dark }} />

      <div className="card-body">
        {/* Header row */}
        <div className="card-header-row">
          <div className="card-icon-label">
            <span className="card-icon">{card.icon}</span>
            <span className="card-label">{card.label}</span>
          </div>
          <span className={`status-pill status-${card.statusTone}`}>
            {card.statusText}
          </span>
        </div>

        {/* Big number */}
        <div className="card-total" style={{ color: colors.text }}>
          {card.total}
        </div>

        {/* Mini swatch row */}
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

        {/* Trend row */}
        <div className="trend-row">
          <TrendArrow dir={card.deltaDir} />
          <span className={`delta-val delta-${card.deltaDir}`}>
            {card.deltaVal}
          </span>
          <span className="delta-text">{card.deltaText}</span>
        </div>

        {/* Sparkline */}
        <Sparkline bars={card.bars} accent={card.accent} />
      </div>
    </div>
  );
}

export default function AgentCardGrid() {
  const totalEvents = CARDS.reduce(
    (sum, c) => sum + parseInt(c.total.replace(/,/g, "")),
    0,
  ).toLocaleString();

  return (
    <div className="dashboard">
      {/* Page header */}
      {/* <div className="page-header">
        <div>
          <h1 className="page-title">
            Card grid overview <span className="arrow-sep">→</span> drill-down
          </h1>
          <p className="page-sub">
            Overview page shows one card per log category with a mini sparkline.
            Clicking a card navigates to the full explorer for that type.
          </p>
        </div>
      </div> */}

      {/* Section bar */}
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

      {/* Cards */}
      <div className="card-grid">
        {CARDS.map((card) => (
          <Card key={card.key} card={card} />
        ))}
      </div>
    </div>
  );
}
