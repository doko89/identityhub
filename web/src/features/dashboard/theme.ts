// Dashboard theme helpers: normalize the admin brand values (or the
// user's local overrides) into concrete styles. Unknown and legacy
// values fall back to the defaults, so old rows and old caches keep
// rendering.

export type DashboardColumns = 2 | 3 | 4;
export type DashboardIconShape = "rounded" | "circle" | "square";
export type DashboardDensity = "comfortable" | "compact";
export type DashboardBackground = "pattern" | "plain" | "photo";

export function normalizeColumns(value: unknown): DashboardColumns {
  if (value === 2 || value === "2") return 2;
  if (value === 4 || value === "4") return 4;
  return 3;
}

export function normalizeIconShape(value: unknown): DashboardIconShape {
  if (value === "circle" || value === "square" || value === "rounded") return value;
  return "rounded";
}

export function normalizeDensity(value: unknown): DashboardDensity {
  if (value === "compact") return "compact";
  return "comfortable";
}

export function normalizeBackground(value: unknown): DashboardBackground {
  if (value === "plain" || value === "photo") return value;
  return "pattern";
}

// DashboardView is the resolved grid geometry: the user's stored
// override wins, otherwise the admin brand default.
export interface DashboardView {
  columns: DashboardColumns;
  density: DashboardDensity;
}

export function resolveDashboardView(
  brand: { dashboard_columns?: unknown; dashboard_density?: unknown } | null | undefined,
  prefs: { columns: DashboardColumns | null; density: DashboardDensity | null },
): DashboardView {
  return {
    columns: prefs.columns ?? normalizeColumns(brand?.dashboard_columns),
    density: prefs.density ?? normalizeDensity(brand?.dashboard_density),
  };
}

// gridClassFor maps the desktop column count onto explicit Tailwind
// classes (dynamic class names would not survive the compiler).
export function gridClassFor(columns: DashboardColumns): string {
  switch (columns) {
    case 2:
      return "grid grid-cols-1 gap-3 sm:grid-cols-2";
    case 4:
      return "grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4";
    default:
      return "grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3";
  }
}

// iconShapeClassFor maps the admin icon shape onto the tile image and
// fallback avatar.
export function iconShapeClassFor(shape: DashboardIconShape): string {
  switch (shape) {
    case "circle":
      return "rounded-full";
    case "square":
      return "rounded-none";
    default:
      return "rounded-md";
  }
}
