import type { DashboardColumns, DashboardDensity } from "./theme";

// Per-device dashboard overrides (direction 2): the user may pick their
// own grid width and density; null follows the admin brand default.
// Stored in localStorage like the theme choice (branding/apply.ts).

export const VIEW_COLUMNS_KEY = "ih-dashboard-columns";
export const VIEW_DENSITY_KEY = "ih-dashboard-density";

export interface DashboardViewPrefs {
  columns: DashboardColumns | null;
  density: DashboardDensity | null;
}

export function getStoredViewPrefs(): DashboardViewPrefs {
  return { columns: getStoredColumns(), density: getStoredDensity() };
}

export function getStoredColumns(): DashboardColumns | null {
  try {
    const raw = localStorage.getItem(VIEW_COLUMNS_KEY);
    if (raw === "2" || raw === "3" || raw === "4") {
      return Number(raw) as DashboardColumns;
    }
    return null;
  } catch {
    return null;
  }
}

export function getStoredDensity(): DashboardDensity | null {
  try {
    const raw = localStorage.getItem(VIEW_DENSITY_KEY);
    if (raw === "comfortable" || raw === "compact") {
      return raw;
    }
    return null;
  } catch {
    return null;
  }
}

export function setStoredColumns(columns: DashboardColumns | null): void {
  storeOrClear(VIEW_COLUMNS_KEY, columns === null ? null : String(columns));
}

export function setStoredDensity(density: DashboardDensity | null): void {
  storeOrClear(VIEW_DENSITY_KEY, density);
}

function storeOrClear(key: string, value: string | null): void {
  try {
    if (value === null) {
      localStorage.removeItem(key);
    } else {
      localStorage.setItem(key, value);
    }
  } catch {
    // Private mode: the choice still applies for this session via state.
  }
}
