"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import {
  AlertStatusBadge,
  EmptyState,
  ErrorBox,
  ScoreCell,
  Spinner,
  StatCard,
} from "@/components/ui";
import { api } from "@/lib/api";
import { cn, formatRelative, formatTime } from "@/lib/format";
import { useTenant } from "@/lib/tenant";
import type { AlertStatus } from "@/lib/types";

const STATUS_FILTERS: Array<{ key: string; label: string }> = [
  { key: "all", label: "All" },
  { key: "escalated", label: "Escalated" },
  { key: "new", label: "New" },
  { key: "triaged", label: "Triaged" },
  { key: "auto_closed", label: "Auto-closed" },
];

export default function AlertQueuePage() {
  const tenant = useTenant();
  const [status, setStatus] = useState<string>("all");

  const alertsQ = useQuery({
    queryKey: ["alerts", tenant, status],
    queryFn: () => api.alerts(status === "all" ? {} : { status }),
    refetchInterval: 4000,
  });

  // For linking escalated alerts to their investigation we map by trigger id.
  const invQ = useQuery({
    queryKey: ["investigations", tenant, "for-linking"],
    queryFn: () => api.investigations({ limit: 50 }),
    refetchInterval: 8000,
  });

  const triggerToInv = useMemo(() => {
    const m = new Map<string, string>();
    for (const inv of invQ.data?.investigations ?? []) {
      if (inv.trigger_alert_id) m.set(inv.trigger_alert_id, inv.id);
    }
    return m;
  }, [invQ.data]);

  // Counts come from the unfiltered list when on "all", else compute locally.
  const allAlerts = alertsQ.data?.alerts ?? [];
  const counts = useMemo(() => {
    const c = { total: 0, escalated: 0, auto_closed: 0 };
    for (const a of allAlerts) {
      c.total += 1;
      if (a.status === "escalated") c.escalated += 1;
      if (a.status === "auto_closed") c.auto_closed += 1;
    }
    return c;
  }, [allAlerts]);

  // The only investigation in the demo, used as a fallback target for
  // escalated alerts that aren't themselves the trigger event.
  const fallbackInv = invQ.data?.investigations?.[0]?.id;

  function investigationFor(alertId: string, alertStatus: AlertStatus) {
    if (alertStatus !== "escalated") return null;
    return triggerToInv.get(alertId) ?? fallbackInv ?? null;
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Alert Queue</h1>
          <p className="text-sm text-slate-500">
            Triaged security signals for tenant{" "}
            <span className="font-mono text-slate-300">{tenant}</span>
          </p>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <StatCard label="Total" value={counts.total} />
          <StatCard
            label="Escalated"
            value={counts.escalated}
            accent="text-red-400"
          />
          <StatCard
            label="Auto-closed"
            value={counts.auto_closed}
            accent="text-slate-400"
          />
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {STATUS_FILTERS.map((f) => (
          <button
            key={f.key}
            onClick={() => setStatus(f.key)}
            className={cn(
              "rounded-full border px-3 py-1 text-xs transition-colors",
              status === f.key
                ? "border-slate-500 bg-slate-700 text-slate-100"
                : "border-slate-800 bg-slate-900 text-slate-400 hover:border-slate-700 hover:text-slate-200",
            )}
          >
            {f.label}
          </button>
        ))}
        {alertsQ.isFetching && (
          <span className="ml-2 text-xs text-slate-600">refreshing…</span>
        )}
      </div>

      {alertsQ.isError ? (
        <ErrorBox error={alertsQ.error} />
      ) : alertsQ.isLoading ? (
        <div className="card p-6">
          <Spinner label="Loading alerts…" />
        </div>
      ) : allAlerts.length === 0 ? (
        <EmptyState>
          No alerts for tenant <span className="mx-1 font-mono">{tenant}</span>. Try
          tenant <span className="mx-1 font-mono">teampcp6</span>.
        </EmptyState>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/80 text-left text-[11px] uppercase tracking-wider text-slate-500">
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Source</th>
                  <th className="px-3 py-2 font-medium">Event</th>
                  <th className="px-3 py-2 font-medium">Title</th>
                  <th className="px-3 py-2 font-medium">Sev</th>
                  <th className="px-3 py-2 font-medium">Conf</th>
                  <th className="px-3 py-2 font-medium">Prio</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {allAlerts.map((a) => {
                  const invId = investigationFor(a.id, a.status);
                  return (
                    <tr
                      key={a.id}
                      className={cn(
                        "border-b border-slate-800/60 transition-colors hover:bg-slate-800/40",
                        a.status === "auto_closed" && "opacity-60",
                      )}
                    >
                      <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                        <div>{formatTime(a.ts)}</div>
                        <div className="text-[11px] text-slate-600">
                          {formatRelative(a.ts)}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <span className="chip">{a.source}</span>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-slate-300">
                        {a.source_event_type}
                      </td>
                      <td className="max-w-[360px] px-3 py-2 text-slate-200">
                        <div className="truncate" title={a.title}>
                          {a.title}
                        </div>
                        {a.actor_identity && (
                          <div className="truncate text-[11px] text-slate-500">
                            {a.actor_identity}
                            {a.source_ip ? ` · ${a.source_ip}` : ""}
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <ScoreCell value={a.triage?.severity} />
                      </td>
                      <td className="px-3 py-2">
                        <ScoreCell value={a.triage?.confidence} />
                      </td>
                      <td className="px-3 py-2">
                        <ScoreCell value={a.triage?.priority} />
                      </td>
                      <td className="px-3 py-2">
                        <AlertStatusBadge status={a.status} />
                      </td>
                      <td className="px-3 py-2 text-right">
                        {invId ? (
                          <Link
                            href={`/investigations/${invId}`}
                            className="inline-flex items-center gap-1 rounded border border-red-500/40 bg-red-500/10 px-2 py-1 text-xs text-red-300 hover:bg-red-500/20"
                          >
                            Investigation
                            <ArrowUpRight className="h-3 w-3" />
                          </Link>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
