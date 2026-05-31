"use client";

import { Cpu, Fingerprint, MonitorSmartphone, Package, Radio } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { streamUrl } from "@/lib/api";
import { useTenant } from "@/lib/tenant";
import type { AgentName, Finding } from "@/lib/types";

const AGENT_META: Record<AgentName, { label: string; icon: typeof Cpu; color: string }> = {
  identity: { label: "Identity", icon: Fingerprint, color: "text-violet-300" },
  endpoint: { label: "Endpoint", icon: MonitorSmartphone, color: "text-amber-300" },
  supplychain: { label: "Supply Chain", icon: Package, color: "text-cyan-300" },
};

interface TraceEvent {
  id: number;
  type: string;
  raw: Record<string, unknown>;
  at: number;
}

// Live trace feed via native EventSource. Appends `trace` events as they
// arrive; `ping` is heartbeat-only and ignored.
function useTraceStream(investigationId: string) {
  const tenant = useTenant();
  const [events, setEvents] = useState<TraceEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const counter = useRef(0);

  useEffect(() => {
    setEvents([]);
    counter.current = 0;
    let es: EventSource | null = null;
    try {
      es = new EventSource(streamUrl(investigationId));
    } catch {
      return;
    }
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    const onTrace = (ev: MessageEvent) => {
      let parsed: Record<string, unknown> = {};
      try {
        parsed = JSON.parse(ev.data);
      } catch {
        parsed = { type: "trace", data: ev.data };
      }
      const type = (parsed.type as string) || "trace";
      setEvents((prev) => [
        ...prev.slice(-80),
        { id: counter.current++, type, raw: parsed, at: Date.now() },
      ]);
    };
    es.addEventListener("trace", onTrace as EventListener);

    return () => {
      es?.removeEventListener("trace", onTrace as EventListener);
      es?.close();
    };
  }, [investigationId, tenant]);

  return { events, connected };
}

function traceLabel(t: TraceEvent): string {
  const r = t.raw;
  switch (t.type) {
    case "investigation.created":
      return "Investigation created";
    case "agents.start":
      return "Agents dispatched";
    case "agent.done":
      return `Agent finished${r.agent ? `: ${r.agent}` : ""}`;
    case "correlated":
      return "Signals correlated into kill chain";
    case "narrative":
      return "Narrative synthesized";
    case "actions.staged":
      return `Response actions staged${r.count ? ` (${r.count})` : ""}`;
    default:
      return t.type;
  }
}

export function AgentTimeline({
  investigationId,
  findings,
}: {
  investigationId: string;
  findings: Finding[];
}) {
  const { events, connected } = useTraceStream(investigationId);

  return (
    <div className="card p-4">
      <h2 className="mb-3 flex items-center justify-between text-sm font-semibold text-slate-200">
        <span className="flex items-center gap-2">
          <Cpu className="h-4 w-4 text-sky-400" />
          Agent Activity
        </span>
        <span className="flex items-center gap-1.5 text-[11px] font-normal text-slate-500">
          <Radio
            className={connected ? "h-3 w-3 text-emerald-400" : "h-3 w-3 text-slate-600"}
          />
          {connected ? "live" : "idle"}
        </span>
      </h2>

      {/* Live trace feed. */}
      <div className="mb-4 max-h-40 space-y-1 overflow-y-auto rounded-md border border-slate-800 bg-[#0b0f17] p-2 font-mono text-[11px]">
        {events.length === 0 ? (
          <div className="px-1 py-2 text-slate-600">
            Listening for live trace events…
          </div>
        ) : (
          events.map((e) => (
            <div key={e.id} className="flex items-start gap-2">
              <span className="text-slate-600">
                {new Date(e.at).toLocaleTimeString()}
              </span>
              <span className="text-sky-300">{traceLabel(e)}</span>
            </div>
          ))
        )}
      </div>

      {/* Persisted per-agent findings with IOCs. */}
      <div className="space-y-3">
        {findings.length === 0 ? (
          <div className="text-sm text-slate-500">No agent findings recorded.</div>
        ) : (
          findings.map((f, idx) => {
            const meta = AGENT_META[f.agent] ?? {
              label: f.agent,
              icon: Cpu,
              color: "text-slate-300",
            };
            const Icon = meta.icon;
            return (
              <div
                key={`${f.agent}-${idx}`}
                className="rounded-md border border-slate-800 bg-slate-900/60 p-3"
              >
                <div className="flex items-center justify-between">
                  <span className={`flex items-center gap-1.5 text-sm font-medium ${meta.color}`}>
                    <Icon className="h-4 w-4" />
                    {meta.label} agent
                  </span>
                  <span className="text-[11px] text-slate-600">
                    {f.iocs.length} IOC{f.iocs.length === 1 ? "" : "s"}
                    {f.latency_ms ? ` · ${f.latency_ms}ms` : ""}
                    {f.tokens ? ` · ${f.tokens} tok` : ""}
                  </span>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-slate-400">
                  {f.summary}
                </p>
                {f.iocs.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {f.iocs.map((ioc, i) => (
                      <span
                        key={`${ioc.type}-${ioc.value}-${i}`}
                        className="chip max-w-full truncate"
                        title={`${ioc.type}: ${ioc.value}`}
                      >
                        <span className="text-slate-500">{ioc.type}</span>
                        <span className="text-slate-300">{ioc.value}</span>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
