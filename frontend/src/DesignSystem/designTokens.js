/**
 * What the design system page reads to describe itself.
 *
 * The values are not listed here — they are read from the running page at
 * render time, so this stays a description of the system rather than a second
 * copy of it that can drift from phi.css.
 */

export const COLOR_GROUPS = [
  {
    title: "Surface and ink",
    note: "The page, the paper on it, and the text on that.",
    tokens: [
      { name: "bg", use: "the page itself" },
      { name: "surface", use: "cards, panels, fields" },
      { name: "sunken", use: "table headers, quiet fills" },
      { name: "text", use: "body copy and headings" },
      { name: "muted", use: "labels, hints, captions" },
      { name: "border", use: "hairlines between things" },
      { name: "border-strong", use: "the edge of a control" },
    ],
  },
  {
    title: "Brand",
    note: "Blue marks the one thing that matters most on a screen.",
    tokens: [
      { name: "primary", use: "the main action" },
      { name: "primary-hover", use: "…under the pointer" },
      { name: "accent", use: "selection, links, emphasis" },
      { name: "accent-hover", use: "…under the pointer" },
      { name: "accent-soft", use: "selected rows and chips" },
      { name: "wash", use: "hover on a surface" },
      { name: "on-primary", use: "text on any strong fill" },
      { name: "focus", use: "the keyboard ring" },
    ],
  },
  {
    title: "Status",
    note: "Never the only signal — a word or an icon says it too.",
    tokens: [
      { name: "success", use: "done, healthy, connected" },
      { name: "success-soft", use: "…as a quiet fill" },
      { name: "warning", use: "needs attention soon" },
      { name: "warning-soft", use: "…as a quiet fill" },
      { name: "danger", use: "failed, destructive" },
      { name: "danger-soft", use: "…as a quiet fill" },
    ],
  },
];

/** Every fill in the system, with the text it is meant to carry. */
export const PAIRS = [
  { bg: "surface", fg: "text", label: "body on a card" },
  { bg: "surface", fg: "muted", label: "caption on a card" },
  { bg: "bg", fg: "text", label: "body on the page" },
  { bg: "bg", fg: "muted", label: "caption on the page" },
  { bg: "sunken", fg: "muted", label: "table header" },
  { bg: "primary", fg: "on-primary", label: "primary button" },
  { bg: "accent", fg: "on-primary", label: "accent button" },
  { bg: "accent-soft", fg: "accent", label: "selected chip" },
  { bg: "success", fg: "on-primary", label: "success fill" },
  { bg: "success-soft", fg: "success", label: "success badge" },
  { bg: "warning", fg: "on-primary", label: "warning fill" },
  { bg: "warning-soft", fg: "warning", label: "warning badge" },
  { bg: "danger", fg: "on-primary", label: "danger button" },
  { bg: "danger-soft", fg: "danger", label: "danger badge" },
];

export const TYPE_SCALE = [
  { token: "text-xl", use: "page title", sample: "Capacity report" },
  { token: "text-lg", use: "card or modal title", sample: "Disk partitions" },
  { token: "text-md", use: "panel title", sample: "Agents by status" },
  { token: "text-base", use: "body", sample: "Every agent that reported in the window." },
  { token: "text-sm", use: "label, hint", sample: "Mount point" },
];

export const SPACE_SCALE = ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9"];
export const RADII = ["r-sm", "r-md", "r-lg", "r-xl", "r-full"];
export const SHADOWS = ["sh1", "sh2", "sh3"];

/** #rrggbb / rgb() -> channels. Whatever the browser hands back. */
function toRgb(value) {
  const v = String(value || "").trim().toLowerCase();

  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/.exec(v);
  if (hex) {
    let h = hex[1];
    if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
    if (h.length === 8) h = h.slice(0, 6);
    return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  }

  const rgb = /^rgba?\(([^)]+)\)$/.exec(v);
  if (rgb) return rgb[1].split(",").slice(0, 3).map((n) => parseFloat(n));

  return null;
}

/** The value the page is actually painting for this token, right now. */
export function readToken(name) {
  if (typeof window === "undefined") return "";
  return getComputedStyle(document.documentElement)
    .getPropertyValue(`--${name}`)
    .trim();
}

function luminance(channels) {
  const step = (c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * step(channels[0]) + 0.7152 * step(channels[1]) + 0.0722 * step(channels[2]);
}

/**
 * WCAG contrast between two tokens, as the page is painting them.
 *
 * Measured rather than asserted: this is what makes the page a check and not
 * just a gallery — change a token and the number here moves with it.
 */
export function contrast(backToken, frontToken) {
  const back = toRgb(readToken(backToken));
  const front = toRgb(readToken(frontToken));
  if (!back || !front) return null;

  const l1 = luminance(back);
  const l2 = luminance(front);
  const hi = Math.max(l1, l2);
  const lo = Math.min(l1, l2);
  return (hi + 0.05) / (lo + 0.05);
}
