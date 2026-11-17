import { useEffect, useState } from "react";
import { Monitor, Moon, Sun } from "lucide-react";
import { Button } from "@/shared/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/shared/ui/dropdown-menu";
import {
  applyTheme,
  getStoredTheme,
  normalizeTheme,
  setStoredTheme,
  type ThemeChoice,
} from "./apply";
import { useBrand } from "./BrandProvider";

const options: { value: ThemeChoice; label: string; Icon: typeof Sun }[] = [
  { value: "light", label: "Light", Icon: Sun },
  { value: "dark", label: "Dark", Icon: Moon },
  { value: "system", label: "System", Icon: Monitor },
];

// ThemeToggle is the dashboard header theme switcher (DESIGN.md §5.3):
// light / dark / system, defaulting to the OS. The choice persists in
// localStorage and wins over the server brand default (DESIGN.md §3).
export function ThemeToggle() {
  const brandTheme = useBrand()?.theme;
  const [choice, setChoice] = useState<ThemeChoice>(
    () => getStoredTheme() ?? normalizeTheme(brandTheme) ?? "system",
  );

  // The brand loads after mount; adopt its default unless the user chose.
  useEffect(() => {
    setChoice(getStoredTheme() ?? normalizeTheme(brandTheme) ?? "system");
  }, [brandTheme]);

  function select(next: ThemeChoice): void {
    setStoredTheme(next);
    applyTheme(next);
    setChoice(next);
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="relative" aria-label="Theme">
          <Sun className="size-4 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
          <Moon className="absolute size-4 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
          <span className="sr-only">Toggle theme</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" aria-label="Theme options">
        <DropdownMenuRadioGroup
          value={choice}
          onValueChange={(v) => {
            const next = normalizeTheme(v);
            if (next !== null) {
              select(next);
            }
          }}
        >
          {options.map((opt) => (
            <DropdownMenuRadioItem key={opt.value} value={opt.value}>
              <opt.Icon className="size-4" />
              {opt.label}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
