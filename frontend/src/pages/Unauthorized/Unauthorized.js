import React, { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import useAuth from "../../hooks/useAuth";
import { roleLabels } from "../../utils/authz";
import ShieldLock from "./ShieldLock";
import "./Unauthorized.css";

// Where "Contact Administrator" points, and how long before the auto-redirect.
const ADMIN_EMAIL = "admin@allatone.in";
const REDIRECT_SECONDS = 10;
const THEME_KEY = "app-theme";

function initialTheme() {
  try {
    const saved = window.localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch (_) {
    /* storage blocked */
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

/** Sun (while dark) / moon (while light) — inline SVG, renders identically everywhere. */
function ThemeIcon({ mode }) {
  const common = {
    viewBox: "0 0 24 24",
    width: 18,
    height: 18,
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": true,
  };
  return mode === "dark" ? (
    <svg {...common}>
      <circle cx="12" cy="12" r="4.2" />
      <path d="M12 2.5v2.2M12 19.3v2.2M4.6 4.6l1.6 1.6M17.8 17.8l1.6 1.6M2.5 12h2.2M19.3 12h2.2M4.6 19.4l1.6-1.6M17.8 6.2l1.6-1.6" />
    </svg>
  ) : (
    <svg {...common}>
      <path d="M20 14.6A8 8 0 1 1 9.4 4 6.2 6.2 0 0 0 20 14.6z" />
    </svg>
  );
}

/** Small inline icons for the action buttons (currentColor, crisp at any size). */
const iconProps = {
  viewBox: "0 0 24 24",
  width: 17,
  height: 17,
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 2,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true,
};
const IconBack = () => (
  <svg {...iconProps}>
    <path d="M19 12H5M12 19l-7-7 7-7" />
  </svg>
);
const IconGrid = () => (
  <svg {...iconProps}>
    <rect x="3" y="3" width="7" height="7" rx="1.5" />
    <rect x="14" y="3" width="7" height="7" rx="1.5" />
    <rect x="14" y="14" width="7" height="7" rx="1.5" />
    <rect x="3" y="14" width="7" height="7" rx="1.5" />
  </svg>
);
const IconMail = () => (
  <svg {...iconProps}>
    <rect x="3" y="5" width="18" height="14" rx="2" />
    <path d="m3 7 9 6 9-6" />
  </svg>
);

/** Build the specific reason shown to the user, from the guard's redirect state. */
function buildReason({ requiredRoles, requiredPerm }) {
  if (requiredRoles && requiredRoles.length) {
    return `This page is restricted to ${roleLabels(requiredRoles)}.`;
  }
  if (requiredPerm) {
    return `This page requires the “${requiredPerm}” permission, which your account doesn’t have.`;
  }
  return "";
}

export default function Unauthorized() {
  const navigate = useNavigate();
  const location = useLocation();
  const { role } = useAuth();

  // Derive everything from the guard's redirect state in one memo — location.state
  // is stable per navigation, so this only recomputes when the user arrives anew.
  const { attemptedPath, requiredRoles, requiredPerm } = useMemo(() => {
    const s = location.state || {};
    return {
      attemptedPath: (s.from && s.from.pathname) || null,
      requiredRoles: s.requiredRoles || [],
      requiredPerm: s.requiredPerm || null,
    };
  }, [location.state]);
  const reason = useMemo(
    () => buildReason({ requiredRoles, requiredPerm }),
    [requiredRoles, requiredPerm]
  );

  const [theme, setTheme] = useState(initialTheme);
  const [toastOpen, setToastOpen] = useState(true);
  const [autoRedirect, setAutoRedirect] = useState(true);
  const [secondsLeft, setSecondsLeft] = useState(REDIRECT_SECONDS);
  const headingRef = useRef(null);

  // Move focus to the heading on mount so keyboard/screen-reader users land on
  // the message rather than at the top of the document.
  useEffect(() => {
    if (headingRef.current) headingRef.current.focus();
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch (_) {
      /* storage blocked — choice just won't persist */
    }
  }, [theme]);

  // Toast auto-dismiss.
  useEffect(() => {
    if (!toastOpen) return undefined;
    const t = setTimeout(() => setToastOpen(false), 6000);
    return () => clearTimeout(t);
  }, [toastOpen]);

  // Optional countdown → Dashboard. Cancellable; stops as soon as it's off.
  useEffect(() => {
    if (!autoRedirect) return undefined;
    if (secondsLeft <= 0) {
      navigate("/dashboard", { replace: true });
      return undefined;
    }
    const t = setTimeout(() => setSecondsLeft((s) => s - 1), 1000);
    return () => clearTimeout(t);
  }, [autoRedirect, secondsLeft, navigate]);

  const goBack = () => {
    // If there's no in-app history to go back to, fall back to the dashboard.
    if (window.history.length > 1) navigate(-1);
    else navigate("/dashboard", { replace: true });
  };

  const mailtoHref = useMemo(() => {
    const subject = `Access request${attemptedPath ? `: ${attemptedPath}` : ""}`;
    const body =
      `Hello,\n\nI was denied access to ${attemptedPath || "a restricted page"} ` +
      `${role ? `while signed in as “${role}”` : ""}.\n` +
      `Could you please review my permissions?\n\nThank you.`;
    return `mailto:${ADMIN_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  }, [attemptedPath, role]);

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));

  return (
    <div className="ua" data-theme={theme}>
      <button
        type="button"
        className="ua__theme"
        onClick={toggleTheme}
        aria-pressed={theme === "light"}
        title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      >
        <ThemeIcon mode={theme} />
        <span className="ua__sr-only">
          {theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        </span>
      </button>

      {toastOpen && (
        <div className="ua__toast" role="alert" aria-live="assertive">
          <span className="ua__toast-dot" aria-hidden="true" />
          <span className="ua__toast-text">
            Access denied{reason ? ` — ${reason}` : "."}
          </span>
          <button
            type="button"
            className="ua__toast-close"
            onClick={() => setToastOpen(false)}
            aria-label="Dismiss notification"
          >
            ×
          </button>
        </div>
      )}

      <main className="ua__card" role="region" aria-labelledby="ua-title">
        <nav className="ua__crumb" aria-label="Breadcrumb">
          <ol>
            <li>
              <button type="button" className="ua__crumb-link" onClick={() => navigate("/dashboard")}>
                Home
              </button>
            </li>
            <li aria-hidden="true" className="ua__crumb-sep">
              /
            </li>
            <li className="ua__crumb-current" aria-current="page">
              {attemptedPath || "Restricted page"}
            </li>
          </ol>
        </nav>

        <ShieldLock />

        <p className="ua__eyebrow">Forbidden</p>
        <p className="ua__code" aria-hidden="true">
          403
        </p>
        <h1 id="ua-title" className="ua__title" ref={headingRef} tabIndex={-1}>
          Access Denied
        </h1>
        <p className="ua__message">
          You don&apos;t have permission to access this page. Please contact your administrator if
          you believe this is a mistake.
        </p>
        {reason && <p className="ua__reason">{reason}</p>}

        <div className="ua__actions">
          <button type="button" className="ua__btn" onClick={goBack} aria-label="Go back to the previous page">
            <IconBack />
            Go Back
          </button>
          <button
            type="button"
            className="ua__btn ua__btn--primary"
            onClick={() => navigate("/dashboard")}
            aria-label="Go to the dashboard"
          >
            <IconGrid />
            Go to Dashboard
          </button>
          <a className="ua__btn ua__btn--ghost" href={mailtoHref} aria-label="Contact the administrator by email">
            <IconMail />
            Contact Administrator
          </a>
        </div>

        {autoRedirect ? (
          <div className="ua__countdown" aria-live="polite">
            <div className="ua__progress">
              <span
                className="ua__progress-fill"
                style={{ width: `${(secondsLeft / REDIRECT_SECONDS) * 100}%` }}
              />
            </div>
            <div className="ua__countdown-row">
              <span>
                Redirecting to Dashboard in <strong>{secondsLeft}s</strong>
              </span>
              <button type="button" className="ua__countdown-cancel" onClick={() => setAutoRedirect(false)}>
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <div className="ua__countdown" aria-live="polite">
            <span className="ua__countdown-off">Auto-redirect cancelled — you can stay on this page.</span>
          </div>
        )}
      </main>
    </div>
  );
}
