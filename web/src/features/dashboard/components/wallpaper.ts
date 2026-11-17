// Dashboard wallpaper choices and persistence. Patterns render in the
// brand primary color at low opacity, so they follow dark/light mode
// and branding with no extra work.
export const WALLPAPER_CHOICES = ["plain", "rects", "dots", "rings"] as const;
export type WallpaperChoice = (typeof WALLPAPER_CHOICES)[number];

export const WALLPAPER_LABELS: Record<WallpaperChoice, string> = {
  plain: "Plain",
  rects: "Rounded rectangles",
  dots: "Dots",
  rings: "Rings",
};

const DEFAULT_WALLPAPER: WallpaperChoice = "rects";

// WALLPAPER_STORAGE_KEY holds the dashboard wallpaper choice.
export const WALLPAPER_STORAGE_KEY = "ih-wallpaper";

function isChoice(v: unknown): v is WallpaperChoice {
  return typeof v === "string" && (WALLPAPER_CHOICES as readonly string[]).includes(v);
}

// loadWallpaper reads the saved choice, falling back to the default when
// unset, invalid, or unreadable (private mode).
export function loadWallpaper(): WallpaperChoice {
  try {
    const v = localStorage.getItem(WALLPAPER_STORAGE_KEY);
    return isChoice(v) ? v : DEFAULT_WALLPAPER;
  } catch {
    return DEFAULT_WALLPAPER;
  }
}

export function saveWallpaper(choice: WallpaperChoice): void {
  try {
    localStorage.setItem(WALLPAPER_STORAGE_KEY, choice);
  } catch {
    // Private mode: the choice still applies for this session.
  }
}
