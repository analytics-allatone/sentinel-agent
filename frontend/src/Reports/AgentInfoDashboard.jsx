import React, { useState } from "react";
import GrafanaDashboard from "../components/GrafanaDashboard/GrafanaDashboard";
import "./AgentInfoDashboard.css";

// Grafana's relative-time syntax, so the frame re-queries on every load.
const RANGES = [
  { label: "Last 1 hour", from: "now-1h" },
  { label: "Last 6 hours", from: "now-6h" },
  { label: "Last 24 hours", from: "now-24h" },
  { label: "Last 7 days", from: "now-7d" },
];

// `$__all` is Grafana's own "All" value for a template variable — it selects
// every option the variable's query returns, rather than a literal named one.
const ALL = "$__all";

const OPERATING_SYSTEMS = [ALL, "linux", "windows", "darwin"];

const osLabel = (value) => (value === ALL ? "All" : value);

// Which tab of the dashboard to open (`&dtab=` in the Grafana URL).
const DASHBOARD_TAB = "Full-Analysis-Dashboard";

export default function AgentInfoDashboard() {
  const [agentName, setAgentName] = useState(ALL);
  const [agentInput, setAgentInput] = useState("");
  const [os, setOs] = useState(ALL);
  const [from, setFrom] = useState("now-6h");
  const [theme, setTheme] = useState("auto");

  return (
    <div className="agent-info-page">
      <header className="agent-info-page__head">
        <h1>Agent Info</h1>
        <p>Live Grafana dashboard — every agent and OS unless narrowed below.</p>
      </header>

      {/* <form
        className="agent-info-page__controls"
        onSubmit={(event) => {
          event.preventDefault();
          // Empty box means every agent, which is what the dashboard opens on.
          setAgentName(agentInput.trim() || ALL);
        }}
      >
        <label>
          <span>Agent</span>
          <input
            type="text"
            value={agentInput}
            placeholder="All agents"
            onChange={(event) => setAgentInput(event.target.value)}
          />
        </label>

        <label>
          <span>OS</span>
          <select value={os} onChange={(event) => setOs(event.target.value)}>
            {OPERATING_SYSTEMS.map((name) => (
              <option key={name} value={name}>
                {osLabel(name)}
              </option>
            ))}
          </select>
        </label>

        <label>
          <span>Range</span>
          <select value={from} onChange={(event) => setFrom(event.target.value)}>
            {RANGES.map((range) => (
              <option key={range.from} value={range.from}>
                {range.label}
              </option>
            ))}
          </select>
        </label>

        <label>
          <span>Theme</span>
          <select value={theme} onChange={(event) => setTheme(event.target.value)}>
            <option value="auto">Auto (system)</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
          </select>
        </label>

        <button type="submit">Apply</button>
      </form> */}

      <div className="agent-info-page__frame">
        <GrafanaDashboard
          agentName={agentName}
          os={os}
          from={from}
          to="now"
          timezone="browser"
          extraParams={{ dtab: DASHBOARD_TAB }}
          // Grafana's own chrome stays visible, matching the shared link. Pass
          // kiosk (the component's default) to hide the nav inside the frame.
          kiosk={false}
          theme={theme}
          title={`Agent info — ${agentName}`}
          height="100%"
        />
      </div>
    </div>
  );
}
