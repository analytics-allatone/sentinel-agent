import React from "react";

/**
 * Minimal shield + padlock mark, drawn as inline SVG so it inherits the theme
 * via the CSS gradient tokens. A single soft halo sits behind it; the gentle
 * float is CSS-driven (see .ua__shield) and disabled under reduced motion.
 */
export default function ShieldLock() {
  return (
    <div className="ua__shield" aria-hidden="true">
      <span className="ua__shield-halo" />
      <svg
        className="ua__shield-svg"
        viewBox="0 0 120 132"
        width="92"
        height="101"
        fill="none"
        role="img"
      >
        <defs>
          <linearGradient id="ua-shield-grad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="var(--ua-shield-1)" />
            <stop offset="100%" stopColor="var(--ua-shield-2)" />
          </linearGradient>
        </defs>

        {/* shield body */}
        <path
          d="M60 6 L106 24 V60 C106 92 86 114 60 124 C34 114 14 92 14 60 V24 Z"
          fill="url(#ua-shield-grad)"
        />

        {/* padlock */}
        <rect x="44" y="62" width="32" height="26" rx="6" fill="#fff" />
        <path
          d="M50 62 V55 a10 10 0 0 1 20 0 V62"
          fill="none"
          stroke="#fff"
          strokeWidth="4.5"
          strokeLinecap="round"
        />
        <circle cx="60" cy="73" r="4" fill="var(--ua-shield-2)" />
        <rect x="58.2" y="75" width="3.6" height="8" rx="1.8" fill="var(--ua-shield-2)" />
      </svg>
    </div>
  );
}
