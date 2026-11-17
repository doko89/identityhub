import { useState } from "react";

// Dashboard wallpaper: random rounded rectangles as a fixed full-page
// SVG in the brand primary color at low opacity, so it follows
// dark/light mode and branding with no extra work. The seed rolls once
// per visit: a fresh arrangement every load, stable while you stay.
export function Wallpaper() {
  const [seed] = useState(() => Math.floor(Math.random() * 2 ** 31));
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
