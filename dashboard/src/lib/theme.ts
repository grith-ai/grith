/**
 * Theme constants for the local dashboard (plan task LD1/F4).
 *
 * The FOUC guard lives inline in index.html (it must run before first
 * paint, before any module loads) and reads the same localStorage key with
 * the same resolution order: stored value -> prefers-color-scheme -> dark.
 * Keep the two in sync when changing either.
 */

export const THEME_STORAGE_KEY = "grith-theme";

export type Theme = "dark" | "light";
