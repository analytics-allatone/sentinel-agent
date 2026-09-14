import React, { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import LostRadar from "./LostRadar";
import "./NotFound.css";

// Shared with the 403 page, so a theme chosen on one is honoured by the other.
const THEME_KEY = "app-theme";
const ADMIN_EMAIL = "admin@allatone.in";

/**
 * The pages a lost visitor can actually be sent to. Kept beside the sidebar's
 * own list of built routes: a 404 that only says "not found" leaves the user
 * with nowhere to go, and these are the four places that exist.
 */
const SUGGESTIONS = [
  { to: "/app/dashboard", label: "Dashboard", sub: "Agents, status and activity" },
  { to: "/app/reports/soc2", label: "SOC2 report", sub: "Trust criteria evidence" },
  { to: "/app/reports/capacity", label: "Capacity report", sub: "CPU, memory and storage" },
  { to: "/app/messages", label: "Messages", sub: "Notification channels" },
];

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

const IconArrow = () => (
  <svg {...iconProps} width="15" height="15">
    <path d="M5 12h14M12 5l7 7-7 7" />
  </svg>
);

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

export default function NotFound() {
  const navigate = useNavigate();
  const location = useLocation();
  const [theme, setTheme] = useState(initialTheme);
  const headingRef = useRef(null);

  // The address that missed, exactly as typed — query string and all, since a
  // wrong parameter is as likely a cause as a wrong path.
  const attemptedPath = `${location.pathname}${location.search || ""}`;

  // Land keyboard and screen-reader users on the message, not the page top.
  useEffect(() => {
    if (headingRef.current) headingRef.current.focus();
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch (_) {
      /* storage blocked — the choice just will not persist */
    }
  }, [theme]);

  const goBack = () => {
    // A 404 reached from outside the app has no in-app history to return to.
    if (window.history.length > 1) navigate(-1);
    else navigate("/app/dashboard", { replace: true });
  };

  const mailtoHref = useMemo(() => {
    const subject = `Broken link: ${attemptedPath}`;
    const body =
      `Hello,\n\nThis address returned "page not found":\n${attemptedPath}\n\n` +
      `I reached it from: ${document.referrer || "(typed or bookmarked)"}\n\nThank you.`;
    return `mailto:${ADMIN_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  }, [attemptedPath]);

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));

  return (
    <div className="nf" data-theme={theme}>
      <div className="nf__shapes" aria-hidden="true">
        <span className="nf__shape nf__shape--1" />
        <span className="nf__shape nf__shape--2" />
      </div>

      <button
        type="button"
        className="nf__theme"
        onClick={toggleTheme}
        aria-pressed={theme === "light"}
        title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      >
        <ThemeIcon mode={theme} />
        <span className="nf__sr-only">
          {theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        </span>
      </button>

      <main className="nf__card" role="region" aria-labelledby="nf-title">
        <LostRadar />

        <p className="nf__eyebrow">Not found</p>
        <p className="nf__code" aria-hidden="true">
          404
        </p>
        <h1 id="nf-title" className="nf__title" ref={headingRef} tabIndex={-1}>
          This page isn&apos;t on the map
        </h1>
        <p className="nf__message">
          The address you asked for doesn&apos;t match anything in Guardlynx. It may have been
          moved, renamed, or mistyped.
        </p>

        <p className="nf__path" title={attemptedPath}>
          {attemptedPath}
        </p>

        <div className="nf__actions">
          <button
            type="button"
            className="nf__btn"
            onClick={goBack}
            aria-label="Go back to the previous page"
          >
            <IconBack />
            Go Back
          </button>
          <button
            type="button"
            className="nf__btn nf__btn--primary"
            onClick={() => navigate("/app/dashboard")}
            aria-label="Go to the dashboard"
          >
            <IconGrid />
            Go to Dashboard
          </button>
          <a
            className="nf__btn"
            href={mailtoHref}
            aria-label="Report this broken link by email"
          >
            <IconMail />
            Report Broken Link
          </a>
        </div>

        <div className="nf__suggest">
          <p className="nf__suggest-title">Try one of these</p>
          <div className="nf__links">
            {SUGGESTIONS.map((s) => (
              <button
                key={s.to}
                type="button"
                className="nf__link"
                onClick={() => navigate(s.to)}
              >
                <span className="nf__link-icon">
                  <IconArrow />
                </span>
                <span className="nf__link-text">
                  <span>{s.label}</span>
                  <span className="nf__link-sub">{s.sub}</span>
                </span>
              </button>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
