"use client";

// Force-directed attack graph. react-force-graph-2d is canvas-only, so it must
// be dynamically imported with ssr:false and rendered in a client component.

import { useQuery } from "@tanstack/react-query";
import dynamic from "next/dynamic";
import { useEffect, useMemo, useRef, useState } from "react";
import { ErrorBox, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { nodeColor } from "@/lib/format";
import { useTenant } from "@/lib/tenant";
import type { GraphNode } from "@/lib/types";

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
  loading: () => (
    <div className="flex h-full items-center justify-center">
      <Spinner label="Loading graph engine…" />
    </div>
  ),
});

type FGNode = GraphNode & { x?: number; y?: number };

const ALL_LABELS = [
  "Alert",
  "Identity",
  "IP",
  "Process",
  "Package",
  "Repository",
  "CloudResource",
  "Asset",
];

export function AttackGraph({ investigationId }: { investigationId: string }) {
  const tenant = useTenant();
  const containerRef = useRef<HTMLDivElement>(null);
  const [dims, setDims] = useState({ width: 600, height: 460 });

  const q = useQuery({
    queryKey: ["graph", tenant, investigationId],
    queryFn: () => api.investigationGraph(investigationId),
  });

  // Track container size so the canvas fills the card responsively.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) {
        setDims({
          width: Math.max(320, e.contentRect.width),
          height: Math.max(360, e.contentRect.height),
        });
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const data = useMemo(() => {
    const nodes = (q.data?.nodes ?? []).map((n) => ({ ...n }));
    const ids = new Set(nodes.map((n) => n.id));
    // Drop dangling edges so the engine doesn't crash on missing endpoints.
    const links = (q.data?.edges ?? [])
      .filter((e) => ids.has(e.source) && ids.has(e.target))
      .map((e) => ({ ...e }));
    return { nodes, links };
  }, [q.data]);

  const presentLabels = useMemo(
    () => ALL_LABELS.filter((l) => data.nodes.some((n) => n.label === l)),
    [data.nodes],
  );

  if (q.isError) return <ErrorBox error={q.error} />;

  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-4 py-2">
        <h2 className="text-sm font-semibold text-slate-200">Attack Graph</h2>
        <div className="flex flex-wrap items-center gap-2">
          {presentLabels.map((l) => (
            <span
              key={l}
              className="inline-flex items-center gap-1 text-[11px] text-slate-400"
            >
              <span
                className="inline-block h-2.5 w-2.5 rounded-full"
                style={{ backgroundColor: nodeColor(l) }}
              />
              {l}
            </span>
          ))}
        </div>
      </div>
      <div ref={containerRef} className="h-[460px] w-full bg-[#0b0f17]">
        {q.isLoading ? (
          <div className="flex h-full items-center justify-center">
            <Spinner label="Loading graph…" />
          </div>
        ) : data.nodes.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-slate-500">
            No graph data.
          </div>
        ) : (
          <ForceGraph2D
            width={dims.width}
            height={dims.height}
            graphData={data}
            backgroundColor="#0b0f17"
            cooldownTicks={120}
            nodeRelSize={5}
            linkColor={() => "rgba(148,163,184,0.25)"}
            linkDirectionalArrowLength={3}
            linkDirectionalArrowRelPos={1}
            linkLabel={(l: { rel?: string }) => l.rel ?? ""}
            nodeLabel={(n: FGNode) =>
              `<div style="font-family:ui-monospace;font-size:11px">
                 <b>${n.label}</b>${n.severity ? ` · ${n.severity}` : ""}<br/>${escapeHtml(
                   n.value,
                 )}
               </div>`
            }
            nodeCanvasObject={(node: FGNode, ctx, globalScale) => {
              const isAlert = node.label === "Alert";
              const r = isAlert ? 6 : 4;
              const x = node.x ?? 0;
              const y = node.y ?? 0;
              // Distinct ring for Alert nodes so they stand out from entities.
              ctx.beginPath();
              ctx.arc(x, y, r, 0, 2 * Math.PI);
              ctx.fillStyle = nodeColor(node.label);
              ctx.fill();
              if (isAlert) {
                ctx.lineWidth = 1.5 / globalScale;
                ctx.strokeStyle = "#fca5a5";
                ctx.stroke();
              }
              // Label entity nodes when zoomed in enough to stay readable.
              if (globalScale > 1.3) {
                const label = truncate(node.value, 22);
                ctx.font = `${10 / globalScale}px ui-monospace`;
                ctx.fillStyle = "#cbd5e1";
                ctx.textAlign = "center";
                ctx.textBaseline = "top";
                ctx.fillText(label, x, y + r + 1);
              }
            }}
          />
        )}
      </div>
      <div className="border-t border-slate-800 px-4 py-1.5 text-[11px] text-slate-600">
        {data.nodes.length} nodes · {data.links.length} edges · drag to explore,
        scroll to zoom
      </div>
    </div>
  );
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
