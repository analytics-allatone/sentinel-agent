import React, { useCallback, useEffect, useState } from "react";
import { LuMoon, LuSun } from "react-icons/lu";

import { applyTheme, readStoredTheme, resolveTheme, systemTheme } from "./theme";
import "./ThemeToggle.css";

/**
 * Light / dark, in one button.
 *
 * It shows what a press will *do* — a moon while the page is light, a sun while
 * it is dark — and says so out loud for anyone who cannot see the icon.
 *
 * Until someone presses it the app follows the operating system, and keeps
 * following it: the listener below is what makes a machine that switches to
 * dark at sunset switch the app too.
 */
export default function ThemeToggle({ className = "" }) {
  const [theme, setTheme] = useState(resolveTheme);

  useEffect(() => {
    if (!window.matchMedia) return undefined;

    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      if (!readStoredTheme()) setTheme(systemTheme());
    };

    // Safari below 14 only has the deprecated form.
    if (query.addEventListener) query.addEventListener("change", onChange);
    else query.addListener(onChange);

    return () => {
      if (query.removeEventListener) query.removeEventListener("change", onChange);
      else query.removeListener(onChange);
    };
  }, []);

  const toggle = useCallback(() => {
    setTheme(applyTheme(theme === "dark" ? "light" : "dark"));
  }, [theme]);

  const dark = theme === "dark";

  return (
    <button
      type="button"
      className={`phi-btn phi-btn--secondary phi-btn--icon phi-btn--sm phi-theme-toggle ${className}`.trim()}
      onClick={toggle}
      aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
      title={dark ? "Switch to light theme" : "Switch to dark theme"}
    >
      {dark ? <LuSun aria-hidden="true" /> : <LuMoon aria-hidden="true" />}
    </button>
  );
}
