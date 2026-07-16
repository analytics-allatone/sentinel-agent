/**
 * Recharts takes real colour values as props, not CSS custom properties, so the
 * series palette lives here and is imported by the chart code. The same hexes are
 * mirrored as custom properties on `.capacity-dash` in CapacityDashboard.css,
 * which dresses the chrome (panels, borders, text).
 *
 * Keep the two in sync: this file is the source of truth for anything a series
 * is drawn with; the stylesheet is the source of truth for everything else.
 *
 * The light column is SELECTED, not an inversion of the dark one — the dark
 * hexes sit at 1.8–2.7:1 on white, well under the 3:1 floor, so a naive flip
 * would be unreadable. Each light step was re-picked in the same hue family and
 * validated against the white panel (lightness band, chroma floor, contrast, and
 * colour-blind separation for the pairs that actually share a chart).
 *
 * Validation is per co-occurring pair, which is the pairlist this design uses:
 * only mem+sto (pane 2) and acpu+amem (pane 3) are ever drawn together. The stat
 * strip shows all five at once but each card carries a text label, so identity
 * there never rests on hue alone.
 */

/** Dark steps — the values specified for the dashboard. */
const DARK = {
  cpu: "#F2A93B",
  mem: "#56C7F2",
  sto: "#8B7FE8",
  acpu: "#4FD6A0",
  amem: "#F2748D",
  // bandwidth arrived later and had no specified colour; blue was the free slot.
  // Validated alone (it is the only series on its pane): band PASS, chroma PASS,
  // contrast >= 3:1 on the dark panel.
  bw: "#4A90E2",
};

/**
 * Light steps — same hue families, re-stepped for the white panel.
 * Validated: band PASS, chroma PASS, contrast all >= 3:1,
 * pane2 deutan dE 11.4, pane3 protan dE 11.5.
 * The green is deliberately dark so it separates from the pink by lightness as
 * well as hue; green-vs-pink is the classic red/green confusion, and lightness
 * is what carries the pair through it.
 */
const LIGHT = {
  cpu: "#B06A00",
  mem: "#0F7FA6",
  sto: "#5B4FD6",
  acpu: "#00704A",
  amem: "#E8628F",
  bw: "#1D5FD0",
};

export const SERIES_COLORS = { dark: DARK, light: LIGHT };

/** Chart chrome — gridlines, axes and tick labels, per theme. */
export const CHART_CHROME = {
  dark: { grid: "#182231", axis: "#1E2836", tick: "#6B7C93", cursor: "#3E4C60" },
  light: { grid: "#E7E9EE", axis: "#CFD4DE", tick: "#6B7280", cursor: "#9AA1AE" },
};

/** The gap seam is the one deliberately loud mark on the page. */
export const GAP_COLOR = { dark: "#F2748D", light: "#C2185B" };
