// Static SVG asymmetric node-web background.
// Three clusters placed at different quadrants using accent colour at low opacity.
// No client hooks — safe as a Server Component.

const ACCENT = "#9B9FEE";

type Node = { id: string; x: number; y: number; hub?: boolean };
type Edge = [string, string];

// ── Cluster A — upper right, largest ─────────────────────────────────────────
const A: Node[] = [
  { id: "a1", x: 77, y: 17, hub: true  },
  { id: "a2", x: 87, y:  8               },
  { id: "a3", x: 94, y: 20               },
  { id: "a4", x: 91, y: 36               },
  { id: "a5", x: 81, y: 46               },
  { id: "a6", x: 69, y: 40               },
  { id: "a7", x: 63, y: 27               },
  { id: "a8", x: 68, y: 12               },
  { id: "a9", x: 83, y: 27               },
];
const AE: Edge[] = [
  ["a1","a2"],["a1","a7"],["a1","a8"],["a1","a9"],
  ["a2","a3"],["a2","a8"],["a3","a4"],["a3","a9"],
  ["a4","a5"],["a4","a9"],["a5","a6"],["a6","a7"],
  ["a7","a8"],["a5","a9"],["a9","a6"],
];

// ── Cluster B — lower left, medium ───────────────────────────────────────────
const B: Node[] = [
  { id: "b1", x: 14, y: 70, hub: true  },
  { id: "b2", x:  4, y: 61               },
  { id: "b3", x: 22, y: 59               },
  { id: "b4", x: 31, y: 67               },
  { id: "b5", x: 26, y: 80               },
  { id: "b6", x: 14, y: 87               },
  { id: "b7", x:  5, y: 79               },
];
const BE: Edge[] = [
  ["b1","b2"],["b1","b3"],["b1","b7"],
  ["b2","b3"],["b2","b7"],["b3","b4"],
  ["b4","b5"],["b5","b6"],["b6","b7"],
  ["b1","b5"],["b1","b6"],
];

// ── Cluster C — upper left, sparse ───────────────────────────────────────────
const C: Node[] = [
  { id: "c1", x:  8, y: 22               },
  { id: "c2", x: 17, y: 11               },
  { id: "c3", x: 25, y: 20               },
  { id: "c4", x: 21, y: 32               },
  { id: "c5", x: 10, y: 31               },
];
const CE: Edge[] = [
  ["c1","c2"],["c2","c3"],["c3","c4"],["c4","c5"],["c5","c1"],["c2","c4"],
];

function renderCluster(nodes: Node[], edges: Edge[]) {
  const map = Object.fromEntries(nodes.map(n => [n.id, n]));
  return (
    <g>
      {edges.map(([a, b]) => {
        const na = map[a], nb = map[b];
        return (
          <line
            key={`${a}-${b}`}
            x1={na.x} y1={na.y} x2={nb.x} y2={nb.y}
            stroke={ACCENT}
            strokeOpacity={0.18}
            strokeWidth={0.5}
            vectorEffect="non-scaling-stroke"
          />
        );
      })}
      {nodes.map(n => (
        <g key={n.id}>
          {n.hub && (
            <circle
              cx={n.x} cy={n.y}
              r={1.4}
              fill="none"
              stroke={ACCENT}
              strokeOpacity={0.2}
              strokeWidth={0.5}
              vectorEffect="non-scaling-stroke"
            />
          )}
          <circle
            cx={n.x} cy={n.y}
            r={n.hub ? 0.75 : 0.45}
            fill={ACCENT}
            fillOpacity={n.hub ? 0.55 : 0.28}
          />
        </g>
      ))}
    </g>
  );
}

export function WebNetworkBg() {
  return (
    <svg
      aria-hidden
      className="pointer-events-none fixed inset-0 z-0 h-full w-full"
      viewBox="0 0 100 100"
      preserveAspectRatio="xMidYMid slice"
    >
      {renderCluster(A, AE)}
      {renderCluster(B, BE)}
      {renderCluster(C, CE)}
    </svg>
  );
}
