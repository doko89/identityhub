import { Check, Image as ImageIcon } from "lucide-react";
import { Button } from "@/shared/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/shared/ui/dropdown-menu";
import {
  WALLPAPER_CHOICES,
  WALLPAPER_LABELS,
  type WallpaperChoice,
} from "./wallpaper";

// mulberry32 is a tiny seeded PRNG: each choice renders the same
// arrangement on every load instead of reshuffling each visit.
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const VIEW_W = 1200;
const VIEW_H = 800;

function roundedRects(seed: number): React.ReactNode[] {
  const rand = mulberry32(seed);
  const shapes: React.ReactNode[] = [];
  for (let i = 0; i < 16; i++) {
    const w = 60 + rand() * 220;
    const h = 40 + rand() * 150;
    const x = rand() * VIEW_W - w / 2;
    const y = rand() * VIEW_H - h / 2;
    const rx = 16 + rand() * 32;
    const rot = (rand() * 24 - 12).toFixed(1);
    shapes.push(
      <rect
        key={i}
        x={x.toFixed(1)}
        y={y.toFixed(1)}
        width={w.toFixed(1)}
        height={h.toFixed(1)}
        rx={rx.toFixed(1)}
        fill="currentColor"
        opacity={(0.45 + rand() * 0.55).toFixed(2)}
        transform={`rotate(${rot} ${(x + w / 2).toFixed(1)} ${(y + h / 2).toFixed(1)})`}
      />,
    );
  }
  return shapes;
}

function dots(seed: number): React.ReactNode[] {
  const rand = mulberry32(seed);
  const shapes: React.ReactNode[] = [];
  const cols = 14;
  const rows = 9;
  for (let cx = 0; cx < cols; cx++) {
    for (let cy = 0; cy < rows; cy++) {
      const x = ((cx + 0.5) / cols) * VIEW_W + (rand() * 24 - 12);
      const y = ((cy + 0.5) / rows) * VIEW_H + (rand() * 24 - 12);
      shapes.push(
        <circle
          key={`${cx}-${cy}`}
          cx={x.toFixed(1)}
          cy={y.toFixed(1)}
          r={(2.5 + rand() * 5).toFixed(1)}
          fill="currentColor"
          opacity={(0.4 + rand() * 0.6).toFixed(2)}
        />,
      );
    }
  }
  return shapes;
}

function rings(seed: number): React.ReactNode[] {
  const rand = mulberry32(seed);
  const shapes: React.ReactNode[] = [];
  for (let i = 0; i < 12; i++) {
    shapes.push(
      <circle
        key={i}
        cx={(rand() * VIEW_W).toFixed(1)}
        cy={(rand() * VIEW_H).toFixed(1)}
        r={(24 + rand() * 80).toFixed(1)}
        fill="none"
        stroke="currentColor"
        strokeWidth={(2 + rand() * 4).toFixed(1)}
        opacity={(0.45 + rand() * 0.55).toFixed(2)}
      />,
    );
  }
  return shapes;
}

const GENERATORS: Record<Exclude<WallpaperChoice, "plain">, (seed: number) => React.ReactNode[]> = {
  rects: roundedRects,
  dots,
  rings,
};

const SEEDS: Record<Exclude<WallpaperChoice, "plain">, number> = {
  rects: 20261117,
  dots: 424242,
  rings: 777001,
};

// Wallpaper renders the dashboard backdrop: a fixed, pointer-transparent
// SVG behind the content. Plain renders nothing.
export function Wallpaper({ choice }: { choice: WallpaperChoice }) {
  if (choice === "plain") {
    return null;
  }
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 overflow-hidden text-primary opacity-[0.08] dark:opacity-[0.12]"
    >
      <svg
        width="100%"
        height="100%"
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        preserveAspectRatio="xMidYMid slice"
      >
        {GENERATORS[choice](SEEDS[choice])}
      </svg>
    </div>
  );
}

// WallpaperPicker switches the dashboard backdrop. State and persistence
// stay with the caller (dashboard page).
export function WallpaperPicker({
  value,
  onChange,
}: {
  value: WallpaperChoice;
  onChange: (next: WallpaperChoice) => void;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="Wallpaper">
          <ImageIcon className="size-4" aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" aria-label="Wallpaper choices">
        {WALLPAPER_CHOICES.map((c) => (
          <DropdownMenuItem key={c} onSelect={() => onChange(c)}>
            <span className="flex w-full items-center justify-between gap-6">
              {WALLPAPER_LABELS[c]}
              {c === value && <Check className="size-4" aria-hidden="true" />}
            </span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
