/**
 * chartPalette - canonical colour values for chart renderers.
 *
 * SVG presentation attributes and canvas renderers need literal colour
 * values at runtime; `var(--g-*)` does not resolve inside SVG attributes.
 * This module mirrors the dark-theme defaults in src/grith-theme.css
 * (canonical source: grith-website/packages/theme/src/grith-theme.css) -
 * keep the two in sync when tokens change. Code panels and charts stay on
 * the dark palette in both themes (spec section 7), so these values are
 * theme-fixed by design.
 *
 * This is the per-app chartPalette pattern from the surface extension
 * spec section 7 (task LD3), mirroring the website's
 * apps/web/src/lib/chartPalette.ts.
 */

export const chartColors = {
  /* accent + status (verdict) colours */
  accent: '#00e5a0',
  accentStrong: '#00f3aa',
  accentInk: '#05140e',
  warning: '#e0a44a',
  danger: '#ff5c5c',

  /* categorical extras */
  info: '#4da6ff',
  purple: '#b392f0',

  /* structure */
  text: '#e9f0ec',
  muted: '#8b978f',
  faint: '#5c665f',
  border: '#1f2a24',
  surface: '#111815',
  surface2: '#0c110e',
  bg: '#0a0f0d',
  codeBg: '#0b100e',
} as const;

/** Status series for verdict charts: allow / queue / deny, always in this order. */
export const statusPalette = [
  chartColors.accent,
  chartColors.warning,
  chartColors.danger,
] as const;

/**
 * Categorical series (providers, agents, projects, filters as categories),
 * fixed assignment order. Six or more categories: keep the top five and
 * collapse the rest into "other" at chartColors.faint.
 */
export const categoricalPalette = [
  chartColors.accent,
  chartColors.info,
  chartColors.purple,
  chartColors.warning,
  chartColors.muted,
] as const;

/** rgba() form of a palette hex for tint fills and intensity ramps. */
export function withAlpha(hex: string, alpha: number): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}
