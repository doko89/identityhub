import { LayoutGrid } from "lucide-react";
import { Button } from "@/shared/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/shared/ui/dropdown-menu";
import type { DashboardColumns, DashboardDensity } from "../theme";

// DashboardViewMenu lets the user override the admin grid geometry for
// this device. "Default" clears the override so the brand wins again.
// State lives in the page; this menu only reports choices.
export function DashboardViewMenu({
  columns,
  density,
  onColumns,
  onDensity,
}: {
  columns: DashboardColumns | null;
  density: DashboardDensity | null;
  onColumns: (columns: DashboardColumns | null) => void;
  onDensity: (density: DashboardDensity | null) => void;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" aria-label="Dashboard view options">
          <LayoutGrid className="size-4" aria-hidden="true" />
          <span className="hidden sm:inline">View</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" aria-label="Dashboard view">
        <DropdownMenuLabel>Columns</DropdownMenuLabel>
        <DropdownMenuRadioGroup
          value={columns === null ? "auto" : String(columns)}
          onValueChange={(v) =>
            onColumns(v === "auto" ? null : (Number(v) as DashboardColumns))
          }
        >
          <DropdownMenuRadioItem value="auto">Default</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="2">2 columns</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="3">3 columns</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="4">4 columns</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
        <DropdownMenuSeparator />
        <DropdownMenuLabel>Density</DropdownMenuLabel>
        <DropdownMenuRadioGroup
          value={density ?? "auto"}
          onValueChange={(v) => onDensity(v === "auto" ? null : (v as DashboardDensity))}
        >
          <DropdownMenuRadioItem value="auto">Default</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="comfortable">Comfortable</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="compact">Compact</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
