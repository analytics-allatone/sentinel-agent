import React from "react";

/**
 * A radar scope with nothing on it — the 404 counterpart to the 403 page's
 * shield. Drawn inline so it inherits the theme through the CSS tokens, and so
 * the sweep can be animated in CSS (and stopped under reduced motion).
 *
 * The dashed trail running off the edge is the point of the drawing: the route
 * the user asked for went somewhere the app does not cover.
 */
export default function LostRadar() {
  return (
    <div className="nf__radar" aria-hidden="true">
      <span className="nf__radar-halo" />

      <svg
        className="nf__radar-svg"
        viewBox="0 0 132 132"
        width="104"
        height="104"
        fill="none"
        role="img"
      >
        <defs>
          <linearGradient id="nf-scope-grad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="var(--nf-mark-1)" />
            <stop offset="100%" stopColor="var(--nf-mark-2)" />
          </linearGradient>
          <linearGradient id="nf-sweep-grad" x1="0.5" y1="0.5" x2="1" y2="0.1">
            <stop offset="0%" stopColor="var(--nf-mark-1)" stopOpacity="0.55" />
            <stop offset="100%" stopColor="var(--nf-mark-1)" stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* scope face */}
        <circle cx="66" cy="66" r="52" fill="var(--nf-scope-fill)" />
        <circle cx="66" cy="66" r="52" stroke="url(#nf-scope-grad)" strokeWidth="3" />
        <circle cx="66" cy="66" r="35" stroke="var(--nf-scope-ring)" strokeWidth="1.5" />
        <circle cx="66" cy="66" r="18" stroke="var(--nf-scope-ring)" strokeWidth="1.5" />

        {/* crosshairs */}
        <path
          d="M66 14v104M14 66h104"
          stroke="var(--nf-scope-ring)"
          strokeWidth="1.5"
          strokeLinecap="round"
        />

        {/* the sweep — rotated by CSS */}
        <g className="nf__radar-sweep">
          <path d="M66 66 L118 66 A52 52 0 0 0 92 21 Z" fill="url(#nf-sweep-grad)" />
        </g>

        {/* two contacts the scope did find */}
        <circle cx="44" cy="52" r="3.4" fill="var(--nf-mark-2)" />
        <circle cx="82" cy="88" r="2.6" fill="var(--nf-mark-2)" opacity="0.7" />

        {/* and the one it did not: a trail leaving the scope, ending nowhere */}
        <path
          d="M66 66 C80 60 94 56 108 44"
          stroke="var(--nf-trail)"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeDasharray="5 7"
        />
        <g className="nf__radar-miss">
          <circle cx="112" cy="40" r="10" fill="var(--nf-miss-fill)" />
          <path
            d="M108 36l8 8M116 36l-8 8"
            stroke="var(--nf-miss-mark)"
            strokeWidth="2.6"
            strokeLinecap="round"
          />
        </g>
      </svg>
    </div>
  );
}
