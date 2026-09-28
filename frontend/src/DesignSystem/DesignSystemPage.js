import React, { useCallback, useEffect, useState } from "react";
import { LuCircleCheck, LuTriangleAlert, LuInbox } from "react-icons/lu";

import ThemeToggle from "../theme/ThemeToggle";
import { resolveTheme, subscribeToTheme } from "../theme/theme";
import {
  COLOR_GROUPS,
  PAIRS,
  RADII,
  SHADOWS,
  SPACE_SCALE,
  TYPE_SCALE,
  contrast,
  readToken,
} from "./designTokens";
import "./DesignSystemPage.css";

/**
 * The design system, as the running app paints it.
 *
 * Every value on this page is read from the live stylesheet rather than typed
 * out again, and every contrast figure is measured rather than claimed. That
 * makes it two things at once: the reference for what the system is, and the
 * check that the app still obeys it — change a token and this page moves.
 */
export default function DesignSystemPage() {
  const [theme, setTheme] = useState(resolveTheme);
  const [, force] = useState(0);

  // The swatches read computed values, so they have to be re-read on a change.
  useEffect(
    () =>
      subscribeToTheme((next) => {
        setTheme(next);
        force((n) => n + 1);
      }),
    []
  );

  const redraw = useCallback(() => force((n) => n + 1), []);

  return (
    <div className="ds-page">
      <a className="phi-skip" href="#ds-main">
        Skip to content
      </a>

      <header className="ds-head">
        <div>
          <p className="ds-eyebrow">GuardLynx</p>
          <h1 className="ds-title">Design system</h1>
          <p className="ds-lead">
            Golden ratio, Fibonacci spacing, one navy and one blue. Everything
            below is read from the running stylesheet — if a value here is wrong,
            the app is wrong with it.
          </p>
        </div>

        <div className="ds-head-actions">
          <span className="phi-badge phi-badge--accent">{theme} theme</span>
          <ThemeToggle />
        </div>
      </header>

      <main id="ds-main" tabIndex={-1}>
        {/* ── colour ───────────────────────────────────────── */}
        <section className="ds-section">
          <h2 className="ds-section-title">Colour</h2>
          <p className="ds-section-note">
            Roughly 62% page, 24% navy, 14% blue. The blue is for the one thing
            that matters most on a screen, which is why there is only ever one
            primary action in view.
          </p>

          {COLOR_GROUPS.map((group) => (
            <div className="ds-group" key={group.title}>
              <h3 className="ds-group-title">{group.title}</h3>
              <p className="ds-group-note">{group.note}</p>

              <div className="ds-swatches">
                {group.tokens.map((token) => (
                  <figure className="ds-swatch" key={token.name}>
                    <span
                      className="ds-swatch-chip"
                      style={{ background: `var(--${token.name})` }}
                    />
                    <figcaption>
                      <code className="ds-swatch-name">--{token.name}</code>
                      <span className="ds-swatch-value">{readToken(token.name)}</span>
                      <span className="ds-swatch-use">{token.use}</span>
                    </figcaption>
                  </figure>
                ))}
              </div>
            </div>
          ))}
        </section>

        {/* ── the pairs, measured ──────────────────────────── */}
        <section className="ds-section">
          <h2 className="ds-section-title">Fills and their text</h2>
          <p className="ds-section-note">
            A fill and the text on it are one decision. These ratios are measured
            in this theme, right now: 4.5:1 is the floor for body text.
          </p>

          <div className="phi-table-wrap">
            <table className="phi-table ds-table">
              <thead>
                <tr>
                  <th>Pair</th>
                  <th>Fill</th>
                  <th>Text</th>
                  <th className="ds-num">Contrast</th>
                  <th>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {PAIRS.map((pair) => {
                  const ratio = contrast(pair.bg, pair.fg);
                  // Unknown is its own answer: a browser that cannot report the
                  // computed value has not told us the pair is bad.
                  const verdict =
                    ratio == null
                      ? { label: "Not measured", tone: "" }
                      : ratio >= 4.5
                        ? { label: "Passes", tone: " phi-badge--success" }
                        : { label: "Too close", tone: " phi-badge--danger" };

                  return (
                    <tr key={pair.label}>
                      <td>
                        <span
                          className="ds-pair-sample"
                          style={{
                            background: `var(--${pair.bg})`,
                            color: `var(--${pair.fg})`,
                          }}
                        >
                          {pair.label}
                        </span>
                      </td>
                      <td>
                        <code>--{pair.bg}</code>
                      </td>
                      <td>
                        <code>--{pair.fg}</code>
                      </td>
                      <td className="ds-num">
                        {ratio == null ? "—" : `${ratio.toFixed(2)}:1`}
                      </td>
                      <td>
                        <span className={`phi-badge${verdict.tone}`}>
                          {verdict.label}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* ── type ─────────────────────────────────────────── */}
        <section className="ds-section">
          <h2 className="ds-section-title">Type</h2>
          <p className="ds-section-note">
            16px body at a 1.618 line height, the scale stepped by the same
            ratio. Headings are set in the display face at 1.1.
          </p>

          <div className="phi-card ds-type">
            {TYPE_SCALE.map((step) => (
              <div className="ds-type-row" key={step.token}>
                <div className="ds-type-meta">
                  <code>--{step.token}</code>
                  <span className="ds-swatch-value">{readToken(step.token)}</span>
                  <span className="ds-swatch-use">{step.use}</span>
                </div>
                <p
                  className="ds-type-sample"
                  style={{
                    fontSize: `var(--${step.token})`,
                    fontFamily:
                      step.token === "text-xl" || step.token === "text-lg"
                        ? "var(--font-display)"
                        : "var(--font-body)",
                    lineHeight:
                      step.token === "text-xl" || step.token === "text-lg" ? 1.1 : 1.618,
                  }}
                >
                  {step.sample}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* ── space, radius, shadow ────────────────────────── */}
        <section className="ds-section">
          <h2 className="ds-section-title">Space, radius, depth</h2>
          <p className="ds-section-note">
            Fibonacci: 3, 5, 8, 13, 21, 34, 55, 89, 144. Inside a component 3–13,
            between elements 13–34, between sections 55–144.
          </p>

          <div className="ds-columns">
            <div className="phi-card">
              <h3 className="ds-group-title">Spacing</h3>
              {SPACE_SCALE.map((token) => (
                <div className="ds-space-row" key={token}>
                  <code>--{token}</code>
                  <span className="ds-space-bar" style={{ width: `var(--${token})` }} />
                  <span className="ds-swatch-value">{readToken(token)}</span>
                </div>
              ))}
            </div>

            <div className="phi-card">
              <h3 className="ds-group-title">Radius</h3>
              <div className="ds-radii">
                {RADII.map((token) => (
                  <div className="ds-radius" key={token}>
                    <span
                      className="ds-radius-box"
                      style={{ borderRadius: `var(--${token})` }}
                    />
                    <code>--{token}</code>
                  </div>
                ))}
              </div>

              <h3 className="ds-group-title ds-group-title--spaced">Depth</h3>
              <div className="ds-shadows">
                {SHADOWS.map((token) => (
                  <div className="ds-shadow" key={token} style={{ boxShadow: `var(--${token})` }}>
                    <code>--{token}</code>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* ── components ───────────────────────────────────── */}
        <section className="ds-section">
          <h2 className="ds-section-title">Components</h2>
          <p className="ds-section-note">
            Every control is at least 44px on its shortest side, and every one of
            them keeps its focus ring. Try tabbing through this section.
          </p>

          <div className="ds-columns">
            <div className="phi-card">
              <h3 className="ds-group-title">Buttons</h3>
              <div className="ds-row">
                <button type="button" className="phi-btn" onClick={redraw}>
                  Save changes
                </button>
                <button type="button" className="phi-btn phi-btn--accent">
                  Start free trial
                </button>
                <button type="button" className="phi-btn phi-btn--secondary">
                  Cancel
                </button>
                <button type="button" className="phi-btn phi-btn--ghost">
                  Learn more
                </button>
                <button type="button" className="phi-btn phi-btn--danger">
                  Delete agent
                </button>
              </div>

              <div className="ds-row">
                <button type="button" className="phi-btn phi-btn--sm phi-btn--secondary">
                  Small
                </button>
                <button type="button" className="phi-btn">
                  Medium
                </button>
                <button type="button" className="phi-btn phi-btn--lg phi-btn--accent">
                  Large
                </button>
                <button type="button" className="phi-btn" disabled>
                  Disabled
                </button>
                <button type="button" className="phi-btn" aria-busy="true" disabled>
                  <span className="phi-spinner" aria-hidden="true" />
                  Creating…
                </button>
              </div>
            </div>

            <div className="phi-card">
              <h3 className="ds-group-title">Fields</h3>

              <div className="ds-fields">
                <div className="phi-field">
                  <label className="phi-label" htmlFor="ds-name">
                    Agent name
                  </label>
                  <input className="phi-input" id="ds-name" defaultValue="Linux_testing" />
                  <span className="phi-hint">Letters, numbers and underscores.</span>
                </div>

                <div className="phi-field">
                  <label className="phi-label" htmlFor="ds-group">
                    Group
                  </label>
                  <input
                    className="phi-input"
                    id="ds-group"
                    defaultValue="prod web servers"
                    aria-invalid="true"
                    aria-describedby="ds-group-error"
                  />
                  <span className="phi-error" id="ds-group-error">
                    A group name cannot contain spaces.
                  </span>
                </div>

                <div className="phi-field">
                  <label className="phi-label" htmlFor="ds-note">
                    Note
                  </label>
                  <textarea className="phi-textarea" id="ds-note" defaultValue="" />
                </div>
              </div>
            </div>
          </div>

          <div className="ds-columns">
            <div className="phi-card">
              <h3 className="ds-group-title">Badges</h3>
              <div className="ds-row">
                <span className="phi-badge phi-badge--success">Active</span>
                <span className="phi-badge phi-badge--warning">Pending</span>
                <span className="phi-badge phi-badge--danger">Disconnected</span>
                <span className="phi-badge phi-badge--accent">New</span>
                <span className="phi-badge">Draft</span>
              </div>

              <h3 className="ds-group-title ds-group-title--spaced">Alerts</h3>
              <div className="ds-stack">
                <div className="phi-alert phi-alert--success" role="status">
                  <LuCircleCheck size={21} aria-hidden="true" />
                  <span>Agent deployed. It reported in 4 seconds later.</span>
                </div>
                <div className="phi-alert phi-alert--warning" role="status">
                  <LuTriangleAlert size={21} aria-hidden="true" />
                  <span>/var/log is 96.3% full on Linux_testing.</span>
                </div>
                <div className="phi-alert phi-alert--danger" role="alert">
                  <LuTriangleAlert size={21} aria-hidden="true" />
                  <span>Could not reach the agent. Try again in a moment.</span>
                </div>
              </div>
            </div>

            <div className="phi-card">
              <h3 className="ds-group-title">Data states</h3>

              <div className="ds-stack">
                <div className="ds-skeleton-block">
                  <span className="phi-skeleton" style={{ height: "var(--s5)", width: "62%" }} />
                  <span className="phi-skeleton" style={{ height: "var(--s5)", width: "100%" }} />
                  <span className="phi-skeleton" style={{ height: "var(--s5)", width: "38%" }} />
                </div>

                <div className="phi-empty">
                  <LuInbox size={55} aria-hidden="true" />
                  <p className="phi-empty-title">No agents yet</p>
                  <p>Deploy your first agent to start seeing capacity data here.</p>
                  <button type="button" className="phi-btn">
                    Deploy new agent
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="phi-card">
            <h3 className="ds-group-title">Table</h3>
            <div className="phi-table-wrap">
              <table className="phi-table">
                <thead>
                  <tr>
                    <th>Agent</th>
                    <th>Operating system</th>
                    <th>Status</th>
                    <th className="phi-num">CPU</th>
                    <th className="phi-num">Memory</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Linux_testing</td>
                    <td>Ubuntu 24.04</td>
                    <td>
                      <span className="phi-badge phi-badge--success">Active</span>
                    </td>
                    <td className="phi-num">7.47%</td>
                    <td className="phi-num">1,229 MB</td>
                  </tr>
                  <tr>
                    <td>UpdatedWindowAgent</td>
                    <td>Windows 11 Pro</td>
                    <td>
                      <span className="phi-badge phi-badge--warning">Pending</span>
                    </td>
                    <td className="phi-num">12.10%</td>
                    <td className="phi-num">3,480 MB</td>
                  </tr>
                  <tr>
                    <td>shiv1</td>
                    <td>Oracle Linux 9</td>
                    <td>
                      <span className="phi-badge phi-badge--danger">Disconnected</span>
                    </td>
                    <td className="phi-num">—</td>
                    <td className="phi-num">—</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
