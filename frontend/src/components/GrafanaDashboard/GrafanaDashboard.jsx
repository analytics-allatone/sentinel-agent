import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./GrafanaDashboard.css";

// Where Grafana lives. Overridable per environment (.env.development /
// .env.production) so the host is not baked into the bundle.
//
// An EMPTY value is meaningful and different from an unset one: it means "same
// origin as this app", i.e. Grafana is reached through a reverse proxy (the dev
// server does this in src/setupProxy.js). That is the configuration that works
// while the Grafana server still sends `X-Frame-Options: deny`.
const DEFAULT_BASE_URL ="http://144.24.104.80:3000"
  // process.env.REACT_APP_GRAFANA_URL === undefined
  //   ? "http://144.24.104.80:3000"
  //   : process.env.REACT_APP_GRAFANA_URL;
const DEFAULT_DASHBOARD_PATH =
  process.env.REACT_APP_GRAFANA_DASHBOARD_PATH || "/d/adsn7p8/agent-info";

// How long we wait for the frame's `load` event before calling it a failure.
const DEFAULT_TIMEOUT_MS = 15000;

/**
 * Build a Grafana dashboard URL from its parts.
 *
 * Exported on its own because the same URL is handy outside the frame — the
 * "Open in new tab" link, a share button, an e-mailed report link.
 *
 *  variables : { agent_name: "TestAgent", os: "linux" } -> &var-agent_name=…&var-os=…
 *              Array values are repeated (Grafana multi-value template vars).
 *              Keys already prefixed with "var-" are passed through as-is.
 */
export function buildGrafanaUrl({
  baseUrl = DEFAULT_BASE_URL,
  dashboardPath = DEFAULT_DASHBOARD_PATH,
  orgId = 1,
  from,
  to,
  timezone,
  variables,
  refresh,
  theme,
  kiosk = true,
  extraParams,
} = {}) {
  const params = new URLSearchParams();

  if (orgId !== null && orgId !== undefined) params.set("orgId", String(orgId));
  if (from) params.set("from", String(from));
  if (to) params.set("to", String(to));
  if (timezone) params.set("timezone", String(timezone));

  Object.entries(variables || {}).forEach(([name, value]) => {
    if (value === null || value === undefined || value === "") return;
    const key = name.startsWith("var-") ? name : `var-${name}`;
    if (Array.isArray(value)) {
      value.forEach((one) => params.append(key, String(one)));
    } else {
      params.append(key, String(value));
    }
  });

  if (refresh) params.set("refresh", String(refresh));
  if (theme) params.set("theme", String(theme));

  Object.entries(extraParams || {}).forEach(([key, value]) => {
    if (value === null || value === undefined) return;
    params.set(key, String(value));
  });

  const origin = String(baseUrl).replace(/\/+$/, "");
  const path = `/${String(dashboardPath).replace(/^\/+/, "")}`;
  // `$` is left literal so template-variable values read the way Grafana writes
  // them (`var-os=$__all`, not `var-os=%24__all`). It is a legal query
  // character, and both forms mean the same thing to Grafana.
  let url = `${origin}${path}?${params.toString().replace(/%24/g, "$")}`;

  // `kiosk` is a valueless flag in Grafana — URLSearchParams would emit
  // `kiosk=`, which older Grafana versions do not treat as full kiosk mode.
  if (kiosk === true) url += "&kiosk";
  else if (typeof kiosk === "string" && kiosk) {
    url += `&kiosk=${encodeURIComponent(kiosk)}`;
  }

  return url;
}

/**
 * "auto" follows the OS colour scheme and keeps following it while mounted;
 * "dark" / "light" pin the theme.
 */
function useResolvedTheme(theme) {
  const [prefersDark, setPrefersDark] = useState(() => {
    if (typeof window === "undefined" || !window.matchMedia) return false;
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  useEffect(() => {
    if (theme !== "auto") return undefined;
    if (typeof window === "undefined" || !window.matchMedia) return undefined;

    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = (event) => setPrefersDark(event.matches);

    // Safari < 14 only has the deprecated addListener/removeListener pair.
    if (query.addEventListener) query.addEventListener("change", onChange);
    else query.addListener(onChange);

    return () => {
      if (query.removeEventListener) query.removeEventListener("change", onChange);
      else query.removeListener(onChange);
    };
  }, [theme]);

  if (theme === "dark" || theme === "light") return theme;
  return prefersDark ? "dark" : "light";
}

/**
 * Embeds a Grafana dashboard in a responsive iframe.
 *
 * Every query param the dashboard understands is a prop, so the caller can
 * swap agent / OS / time range at runtime without touching this file:
 *
 *   <GrafanaDashboard
 *     agentName={agent}
 *     os={os}
 *     from="now-24h"
 *     to="now"
 *     theme="dark"
 *     height="calc(100vh - 160px)"
 *   />
 *
 * A note on failure detection: browsers deliberately give the parent page no
 * usable signal when a frame is refused by X-Frame-Options or CSP — Chrome even
 * fires `load` for its own "refused to connect" page, and the frame's document
 * is cross-origin either way. So this component treats "no load event within
 * `timeoutMs`" and the `error` event as failures, and — because a refusal can
 * still slip past both — keeps a permanent one-line hint under the frame
 * pointing at the `allow_embedding` fix.
 */
export default function GrafanaDashboard({
  baseUrl = DEFAULT_BASE_URL,
  dashboardPath = DEFAULT_DASHBOARD_PATH,
  orgId = 1,
  from = "now-6h",
  to = "now",
  timezone = "browser",
  agentName,
  os,
  variables,
  refresh,
  kiosk = true,
  theme = "auto",
  height = "100%",
  minHeight = 480,
  title = "Grafana dashboard",
  timeoutMs = DEFAULT_TIMEOUT_MS,
  helpFooter = true,
  extraParams,
  onLoad,
  onError,
  className = "",
  style,
}) {
  const resolvedTheme = useResolvedTheme(theme);

  // Callers pass these as inline object literals, so compare by value rather
  // than by identity — otherwise the URL would be rebuilt on every render.
  const variablesKey = JSON.stringify(variables || {});
  const extraParamsKey = JSON.stringify(extraParams || {});

  const url = useMemo(
    () =>
      buildGrafanaUrl({
        baseUrl,
        dashboardPath,
        orgId,
        from,
        to,
        timezone,
        // Explicit props win over the generic `variables` bag only when set;
        // anything else the dashboard defines can be passed through `variables`.
        variables: { agent_name: agentName, os, ...(variables || {}) },
        refresh,
        theme: resolvedTheme,
        kiosk,
        extraParams,
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      baseUrl,
      dashboardPath,
      orgId,
      from,
      to,
      timezone,
      agentName,
      os,
      variablesKey,
      refresh,
      resolvedTheme,
      kiosk,
      extraParamsKey,
    ],
  );

  // "loading" -> "ready" | "error". `reloadKey` remounts the frame on retry.
  const [status, setStatus] = useState("loading");
  const [failure, setFailure] = useState(null); // "timeout" | "load"
  const [reachable, setReachable] = useState(null); // null = unknown
  const [reloadKey, setReloadKey] = useState(0);

  const frameRef = useRef(null);
  const onLoadRef = useRef(onLoad);
  const onErrorRef = useRef(onError);
  useEffect(() => {
    onLoadRef.current = onLoad;
    onErrorRef.current = onError;
  }, [onLoad, onError]);

  // Any change to the URL starts a fresh load.
  useEffect(() => {
    setStatus("loading");
    setFailure(null);
  }, [url, reloadKey]);

  // Give up after `timeoutMs` if the frame never reports a load.
  useEffect(() => {
    if (status !== "loading" || !timeoutMs) return undefined;
    const timer = setTimeout(() => {
      setFailure("timeout");
      setStatus("error");
    }, timeoutMs);
    return () => clearTimeout(timer);
  }, [status, timeoutMs, url, reloadKey]);

  // Side probe, only to word the error well: a no-cors request tells us whether
  // the server answered at all (opaque response) or the host is unreachable —
  // it cannot read headers, so it can never confirm embedding is allowed.
  useEffect(() => {
    if (typeof fetch !== "function") return undefined;
    const controller = new AbortController();
    const origin = String(baseUrl).replace(/\/+$/, "");
    setReachable(null);

    fetch(`${origin}/api/health`, {
      mode: "no-cors",
      cache: "no-store",
      signal: controller.signal,
    })
      .then(() => setReachable(true))
      .catch(() => {
        if (!controller.signal.aborted) setReachable(false);
      });

    return () => controller.abort();
  }, [baseUrl, reloadKey]);

  useEffect(() => {
    if (status === "error" && onErrorRef.current) {
      onErrorRef.current({ url, reason: failure, reachable });
    }
  }, [status, failure, reachable, url]);

  const handleLoad = useCallback(() => {
    // A same-origin (reverse-proxied) frame can be inspected: an empty document
    // means the browser committed a blank/error page instead of the dashboard.
    // Cross-origin frames throw or return null here — the browser exposes
    // nothing about a refusal, which is what the footer hint is for.
    try {
      const doc = frameRef.current && frameRef.current.contentDocument;
      if (doc && doc.body && doc.body.childElementCount === 0) {
        setFailure("blocked");
        setStatus("error");
        return;
      }
    } catch (ignored) {
      // Cross-origin: nothing to inspect, treat the load event as success.
    }

    setStatus("ready");
    setFailure(null);
    if (onLoadRef.current) onLoadRef.current({ url });
  }, [url]);

  const handleError = useCallback(() => {
    setFailure("load");
    setStatus("error");
  }, []);

  const retry = useCallback(() => setReloadKey((key) => key + 1), []);

  // "100%" means "fill whatever box the parent gives me" — expressed as
  // flex-grow in CSS, so no inline height is set in that case. A concrete value
  // (400, "60vh", "calc(100vh - 160px)") is applied as-is.
  const fillsParent = height === "100%" || height === undefined;
  const frameHeight = typeof height === "number" ? `${height}px` : height;
  const frameMinHeight = typeof minHeight === "number" ? `${minHeight}px` : minHeight;

  return (
    <div
      className={`grafana-embed ${className}`.trim()}
      data-theme={resolvedTheme}
      data-status={status}
      style={{
        height: fillsParent ? undefined : frameHeight,
        minHeight: frameMinHeight,
        ...style,
      }}
    >
      <div className="grafana-embed__frame-wrap">
        {status !== "error" && (
          <iframe
            key={`${url}#${reloadKey}`}
            ref={frameRef}
            className="grafana-embed__frame"
            src={url}
            title={title}
            onLoad={handleLoad}
            onError={handleError}
            loading="eager"
            allow="fullscreen"
            referrerPolicy="no-referrer-when-downgrade"
          />
        )}

        {status === "loading" && (
          <div className="grafana-embed__overlay" role="status" aria-live="polite">
            <div className="grafana-embed__spinner" />
            <p className="grafana-embed__loading-text">Loading dashboard…</p>
          </div>
        )}

        {status === "error" && (
          <div className="grafana-embed__overlay grafana-embed__overlay--error" role="alert">
            <div className="grafana-embed__error-card">
              <h3 className="grafana-embed__error-title">Dashboard could not be embedded</h3>

              <p className="grafana-embed__error-lead">
                {reachable === false
                  ? "The Grafana server did not respond. Check that it is running and reachable from this browser."
                  : failure === "timeout"
                    ? "Grafana did not finish loading in time. This is usually the browser refusing the frame (X-Frame-Options / Content-Security-Policy)."
                    : failure === "blocked"
                      ? "The frame loaded empty — the browser refused Grafana's response instead of rendering it."
                      : "The browser refused to render the Grafana frame."}
              </p>

              <p className="grafana-embed__error-hint">
                To allow embedding, set this on the Grafana server in
                {" "}
                <code>grafana.ini</code> and restart it:
              </p>

              <pre className="grafana-embed__code">
{`[security]
allow_embedding = true

# Only if Grafana is on a different host or scheme than this app:
cookie_samesite = none

# Optional — lets the panel render without a Grafana login:
[auth.anonymous]
enabled = true`}
              </pre>

              <ul className="grafana-embed__checklist">
                <li>
                  Restart afterwards: <code>sudo systemctl restart grafana-server</code>
                </li>
                <li>
                  Serving this app over <code>https</code> while Grafana is on{" "}
                  <code>http</code> is blocked as mixed content — put Grafana behind
                  TLS too.
                </li>
                <li>
                  Any reverse proxy in front of Grafana must not re-add{" "}
                  <code>X-Frame-Options</code>.
                </li>
              </ul>

              <div className="grafana-embed__actions">
                <button type="button" className="grafana-embed__btn" onClick={retry}>
                  Retry
                </button>
                <a
                  className="grafana-embed__btn grafana-embed__btn--ghost"
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Open in Grafana ↗
                </a>
              </div>

              <p className="grafana-embed__url" title={url}>
                {url}
              </p>
            </div>
          </div>
        )}
      </div>

      {helpFooter && status === "ready" && (
        <div className="grafana-embed__footer">
          <span>
            Frame blank or “refused to connect”? Grafana needs{" "}
            <code>allow_embedding = true</code>.
          </span>
          <a href={url} target="_blank" rel="noopener noreferrer">
            Open in Grafana ↗
          </a>
        </div>
      )}
    </div>
  );
}
