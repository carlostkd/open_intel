"use client";

import { useCallback, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Graph from "graphology";
import Sigma from "sigma";
import { CATEGORY_META, entityTypeToCategory } from "@/lib/types/investigation";
import type { EntityRelatedResponse } from "@/lib/types/entity";

// ─── helpers ────────────────────────────────────────────────────────────────

function buildMiniGraph(data: EntityRelatedResponse): Graph {
  const g = new Graph({ multi: false, type: "undirected" });

  const center = data.entity;
  const centerCat = entityTypeToCategory(center.entity_type);
  const centerColor = CATEGORY_META[centerCat].color;

  // Center node — fixed at (0, 0), larger
  g.addNode(center.id, {
    label: center.value.length > 20 ? `${center.value.slice(0, 18)}…` : center.value,
    x: 0,
    y: 0,
    size: 18,
    color: centerColor,
    origColor: centerColor,
    fixed: true,
    isCenter: true,
    entityId: center.id,
  });

  const neighbors = data.neighbors;
  const total = neighbors.length;

  neighbors.forEach((nbr, i) => {
    const angle = (2 * Math.PI * i) / total - Math.PI / 2;
    const radius = 2.8;
    const x = radius * Math.cos(angle);
    const y = radius * Math.sin(angle);

    const cat = entityTypeToCategory(nbr.entity_type);
    const color = CATEGORY_META[cat].color;
    const label = nbr.value.length > 18 ? `${nbr.value.slice(0, 16)}…` : nbr.value;

    if (!g.hasNode(nbr.id)) {
      g.addNode(nbr.id, {
        label,
        x,
        y,
        size: 9,
        color,
        origColor: color,
        isCenter: false,
        entityId: nbr.id,
        relationshipType: nbr.relationship_type,
      });
    }

    if (!g.hasEdge(center.id, nbr.id)) {
      g.addEdge(center.id, nbr.id, {
        size: 0.5 + nbr.strength * 1.0,
        color: "#333333",
        label: nbr.relationship_type,
      });
    }
  });

  return g;
}

// ─── component ───────────────────────────────────────────────────────────────

type Props = {
  data: EntityRelatedResponse | null;
  loading: boolean;
};

export function EntityMiniGraph({ data, loading }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const sigmaRef = useRef<Sigma | null>(null);
  const router = useRouter();

  // Store router.push in a ref so sigma click handlers don't capture stale values
  const pushRef = useRef(router.push.bind(router));
  pushRef.current = router.push.bind(router);

  const initGraph = useCallback(() => {
    const el = containerRef.current;
    if (!el || !data) return;

    if (sigmaRef.current) {
      sigmaRef.current.kill();
      sigmaRef.current = null;
    }

    if (data.neighbors.length === 0) return;

    const g = buildMiniGraph(data);

    const sigma = new Sigma(g, el, {
      renderLabels: true,
      labelFont: "JetBrains Mono, monospace",
      labelSize: 9,
      labelColor: { color: "#aaaaaa" },
      defaultNodeColor: "#444444",
      defaultEdgeColor: "#333333",
      stagePadding: 32,
      minCameraRatio: 0.3,
      maxCameraRatio: 4,
    });

    sigmaRef.current = sigma;

    sigma.on("enterNode", (ev) => {
      const isCenter = g.getNodeAttribute(ev.node, "isCenter") as boolean;
      if (!isCenter) {
        el.style.cursor = "pointer";
        g.setNodeAttribute(ev.node, "size", 12);
        sigma.refresh();
      }
    });

    sigma.on("leaveNode", (ev) => {
      el.style.cursor = "default";
      const isCenter = g.getNodeAttribute(ev.node, "isCenter") as boolean;
      if (!isCenter) {
        g.setNodeAttribute(ev.node, "size", 9);
        sigma.refresh();
      }
    });

    sigma.on("clickNode", (ev) => {
      const isCenter = g.getNodeAttribute(ev.node, "isCenter") as boolean;
      if (!isCenter) {
        const entityId = g.getNodeAttribute(ev.node, "entityId") as string;
        pushRef.current(`/entities/${encodeURIComponent(entityId)}`);
      }
    });
  }, [data]);

  useEffect(() => {
    initGraph();
    return () => {
      if (sigmaRef.current) {
        sigmaRef.current.kill();
        sigmaRef.current = null;
      }
    };
  }, [initGraph]);

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center font-mono text-[11px] text-neutral-600">
        <span className="animate-pulse">Loading graph…</span>
      </div>
    );
  }

  if (!data || data.neighbors.length === 0) {
    return (
      <div className="flex h-full items-center justify-center font-mono text-[11px] text-neutral-600">
        <div className="text-center">
          <p className="text-neutral-500 mb-1">No relationships found</p>
          <p className="text-[10px] text-neutral-700">This entity has no recorded connections</p>
        </div>
      </div>
    );
  }

  return (
    <div className="relative h-full w-full">
      <div ref={containerRef} className="h-full w-full" />
      <p className="absolute bottom-2 right-2 font-mono text-[9px] text-neutral-700">
        Click neighbor to open profile
      </p>
    </div>
  );
}
