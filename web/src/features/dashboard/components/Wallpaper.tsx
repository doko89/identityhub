import { useState } from "react";
import type { DashboardBackground } from "../theme";

// Dashboard wallpaper, following the admin background choice: random
// rounded rectangles as a fixed full-page SVG in the brand primary
// color at low opacity (the seed rolls once per visit), a plain page,
// or the uploaded photo under a readability scrim. A photo choice
// without a photo falls back to the pattern.
export function Wallpaper({
  background = "pattern",
  photoUrl = "",
}: {
  background?: DashboardBackground;
  photoUrl?: string;
}) {
  const [seed] = useState(() => Math.floor(Math.random() * 2 ** 31));
  if (background === "plain") {
    return null;
  }
  if (background === "photo" && photoUrl !== "") {
    return (
      <div aria-hidden="true" className="pointer-events-none fixed inset-0 overflow-hidden">
        <img src={photoUrl} alt="" className="h-full w-full object-cover" />
        <div className="absolute inset-0 bg-background/60" />
      </div>
    );
  }
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 overflow-hidden text-primary opacity-[0.08] dark:opacity-[0.12]"
    >
      <svg width="100%" height="100%" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice">
        {roundedRects(seed)}
      </svg>
    </div>
  );
}

// mulberry32 is a tiny seeded PRNG.
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

function roundedRects(seed: number): React.ReactNode[] {
  const rand = mulberry32(seed);
  const shapes: React.ReactNode[] = [];
  for (let i = 0; i < 16; i++) {
    const w = 60 + rand() * 220;
    const h = 40 + rand() * 150;
    const x = rand() * 1200 - w / 2;
    const y = rand() * 800 - h / 2;
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
