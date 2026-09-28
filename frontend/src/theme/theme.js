/**
 * Which theme the app is in.
 *
 * Three states, not two: "light" and "dark" are choices the person made, and
 * their absence means "whatever the OS says" — which is the default, and which
 * keeps following the OS as it changes through the day.
 *
 * The first paint is handled in public/index.html, before React exists, so the
 * page never flashes the wrong theme. This module is what changes it after.
 */
export const THEME_KEY = "phi-theme";

/** The stored choice, or null when the OS is still deciding. */
export function readStoredTheme() {
  try {
    const value = localStorage.getItem(THEME_KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch (err) {
    return null; // private browsing refuses storage; the OS still decides
  }
}

/** What the OS asks for right now. */
export function systemTheme() {
  return typeof window !== "undefined" &&
    window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

/** What is actually on screen. */
export function resolveTheme() {
  return readStoredTheme() || systemTheme();
}

/**
 * Watch what is on screen.
 *
 * Two things can change it: the toggle, which stamps the attribute, and the OS,
 * which only matters while nothing is stored. Both are watched, so a screen
 * with its own palette (the capacity report draws its charts from one) can
 * follow along instead of drifting out of step with the rest of the app.
 *
 * Returns the function that stops watching.
 */
export function subscribeToTheme(onChange) {
  const notify = () => onChange(resolveTheme());

  const observer = new MutationObserver(notify);
  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ["data-theme"],
  });

  const query =
    typeof window !== "undefined" && window.matchMedia
      ? window.matchMedia("(prefers-color-scheme: dark)")
      : null;

  if (query) {
    if (query.addEventListener) query.addEventListener("change", notify);
    else query.addListener(notify);
  }

  return () => {
    observer.disconnect();
    if (!query) return;
    if (query.removeEventListener) query.removeEventListener("change", notify);
    else query.removeListener(notify);
  };
}

/**
 * Put a theme on screen, and remember it.
 *
 * Passing null forgets the choice and hands the decision back to the OS.
 */
export function applyTheme(theme) {
  const root = document.documentElement;

  if (theme === "light" || theme === "dark") {
    root.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch (err) {
      // the attribute still holds for this tab
    }
    return theme;
  }

  root.removeAttribute("data-theme");
  try {
    localStorage.removeItem(THEME_KEY);
  } catch (err) {
    // nothing to clean up
  }
  return systemTheme();
}
