/**
 * Dev-server proxy (react-scripts start only — never part of a production build).
 *
 * The backend half is always active. The Grafana half is a FALLBACK, switched on
 * only by setting REACT_APP_GRAFANA_URL empty in .env.development. By default
 * the frame points straight at the Grafana server, exactly like production.
 *
 * Why the fallback exists
 * ───────────────────────
 * The Grafana box answers with `X-Frame-Options: deny`, so the browser refuses
 * to render it in an iframe no matter what the app does. It also 302s anonymous
 * visitors to /login, and its session cookie is SameSite=Lax, which a browser
 * will not send on a cross-site frame request — so even with framing allowed the
 * frame would show a login page.
 *
 * Proxying Grafana through this dev server fixes both: the frame is then
 * same-origin (http://localhost:3000), the X-Frame-Options header is stripped on
 * the way back, and Grafana's cookie becomes first-party.
 *
 * The real fix is server-side. Watch the leading `;` in grafana.ini — it is a
 * comment marker, and `;allow_embedding = true` is the disabled default:
 *
 *   [security]
 *   allow_embedding = true
 *
 *   [auth.anonymous]
 *   enabled = true
 *   org_name = Main Org.
 *   org_role = Viewer
 *
 *   sudo systemctl restart grafana-server
 *
 * In production, the same proxying belongs in nginx in front of the app. Mirror
 * the split below — this app under /app, everything else to Grafana:
 *
 *   location /app/ { try_files $uri /index.html; }
 *   location /api/v1/ { proxy_pass http://80.225.239.163:8000; }
 *   location / {
 *     proxy_pass http://144.24.104.80:3000;
 *     proxy_set_header Host $host;
 *     proxy_set_header Upgrade $http_upgrade;
 *     proxy_set_header Connection "upgrade";
 *     proxy_hide_header X-Frame-Options;
 *   }
 *
 * NOTE: adding this file makes CRA ignore the "proxy" field in package.json, so
 * the backend proxy that field provided is re-declared below, unchanged.
 */
const { createProxyMiddleware } = require("http-proxy-middleware");

const GRAFANA_TARGET =
  process.env.GRAFANA_PROXY_TARGET || "http://144.24.104.80:3000";
const API_TARGET = process.env.API_PROXY_TARGET || "http://80.225.239.163:8000";

// The Grafana half of this file only applies when the app is configured to
// reach Grafana through its OWN origin, i.e. REACT_APP_GRAFANA_URL is empty.
// When that variable names the Grafana server directly (the default), the frame
// talks to it with no proxy in between and the dev server must not claim
// Grafana's root paths.
const PROXY_GRAFANA = process.env.REACT_APP_GRAFANA_URL === "";

// No token knob here on purpose: Grafana honours `Authorization: Bearer` on
// /api/* only. On a dashboard UI route it ignores the header and still 302s to
// /login (verified against this server), so a service-account token cannot
// stand in for a session. The frame is authenticated either by a Grafana login
// in this browser, or by anonymous access enabled on the server.

// Paths this app owns. EVERYTHING else goes to Grafana.
//
// This is a deny-list rather than a list of Grafana paths on purpose: Grafana
// serves dozens of roots (/d, /login, /public, /user, /profile, /admin, /org,
// /explore, /a, /goto, …) and any one of them missing from an allow-list gets
// answered with this app's index.html instead — which is how a session-token
// rotation to /user/auth-tokens/rotate ended up in React Router.
const APP_OWNED = [
  /^\/$/,
  /^\/app(\/|$)/, // every route in App.js lives under /app
  /^\/api\/v1(\/|$)/, // the backend API
  // create-react-app dev-server internals
  /^\/static\//,
  /^\/sockjs-node/,
  /^\/ws(\/|$)/,
  /^\/__webpack/,
  /hot-update\.(json|js)$/,
  /^\/(index\.html|manifest\.json|asset-manifest\.json|favicon\.ico|robots\.txt)$/,
  /^\/logo\d*\.png$/,
];

// A filter function (rather than a mount path) is what makes the websocket
// upgrade handler honour these exclusions too — mounted with app.use(path, …)
// the middleware's own context stays "/" and it would hijack every upgrade,
// including the dev server's own /ws hot-reload socket.
const toGrafana = (pathname) => !APP_OWNED.some((re) => re.test(pathname));

module.exports = function setupProxy(app) {
  // Backend — replaces the "proxy" field this file disables.
  app.use(
    "/api/v1",
    createProxyMiddleware({
      target: API_TARGET,
      changeOrigin: true,
      logLevel: "warn",
    }),
  );

  if (!PROXY_GRAFANA) return;

  app.use(
    createProxyMiddleware(toGrafana, {
      target: "http://144.24.104.80:3000/",
      changeOrigin: true,
      ws: true, // Grafana Live (/api/live/ws)
      secure: false,
      cookieDomainRewrite: "", // drop the Domain attribute -> cookie sticks to localhost
      logLevel: "warn",
      onProxyRes(proxyRes) {
        // The whole point: let the browser frame this response.
        delete proxyRes.headers["x-frame-options"];

        const csp = proxyRes.headers["content-security-policy"];
        if (csp) {
          proxyRes.headers["content-security-policy"] = csp
            .replace(/frame-ancestors[^;]*;?/gi, "")
            .trim();
        }
      },
    }),
  );
};
