"use client";

import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, ShieldX } from "lucide-react";
import { EmptyState, ErrorBox, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { formatTime } from "@/lib/format";
import { useTenant } from "@/lib/tenant";
import type { AuditEvent } from "@/lib/types";

// Compact one-line summary of an audit event's data payload.
function summarizeData(data: Record<string, unknown>): string {
  const keys = ["alert_id", "investigation_id", "action_id", "type", "status", "decision", "source", "event_type"];
  const parts: string[] = [];
  for (const k of keys) {
    if (data[k] != null) parts.push(`${k}=${String(data[k])}`);
  }
  if (parts.length === 0) {
    const entries = Object.entries(data).slice(0, 3);
    for (const [k, v] of entries) {
      if (typeof v !== "object") parts.push(`${k}=${String(v)}`);
    }
  }
  return parts.join("  ");
}

export default function AuditPage() {
  const tenant = useTenant();

  const verifyQ = useQuery({
    queryKey: ["audit-verify", tenant],
    queryFn: () => api.auditVerify(),
    refetchInterval: 6000,
  });
  const eventsQ = useQuery({
    queryKey: ["audit", tenant],
    queryFn: () => api.audit({ limit: 200 }),
    refetchInterval: 6000,
  });

  const v = verifyQ.data;
  const verified = v?.ok === true;
  const events: AuditEvent[] = eventsQ.data?.events ?? [];
  // Newest first.
  const sorted = [...events].sort((a, b) => b.seq - a.seq);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Audit Log</h1>
        <p className="text-sm text-slate-500">
          Tamper-evident hash chain for tenant{" "}
          <span className="font-mono text-slate-300">{tenant}</span>
        </p>
      </div>

      {/* Prominent chain status badge. */}
      {verifyQ.isLoading ? (
        <div className="card p-5">
          <Spinner label="Verifying hash chain…" />
        </div>
      ) : verifyQ.isError ? (
        <ErrorBox error={verifyQ.error} />
      ) : (
        <div
          className={
            verified
              ? "card flex items-center gap-3 border-emerald-500/40 bg-emerald-950/20 p-4"
              : "card flex items-center gap-3 border-red-500/50 bg-red-950/30 p-4"
          }
        >
          {verified ? (
            <ShieldCheck className="h-8 w-8 shrink-0 text-emerald-400" />
          ) : (
            <ShieldX className="h-8 w-8 shrink-0 text-red-400" />
          )}
          <div>
            <div
              className={
                verified
                  ? "text-lg font-semibold text-emerald-300"
                  : "text-lg font-semibold text-red-300"
              }
            >
              {verified
                ? "Chain verified"
                : `BROKEN at index ${v?.broken_index ?? "?"}`}
            </div>
            <div className="text-xs text-slate-500">
              {v?.length ?? 0} events
              {v?.head_hash ? (
                <>
                  {" · head "}
                  <span className="font-mono">{v.head_hash.slice(0, 16)}…</span>
                </>
              ) : null}
              {!verified && v?.reason ? ` · ${v.reason}` : ""}
            </div>
          </div>
        </div>
      )}

      {eventsQ.isError ? (
        <ErrorBox error={eventsQ.error} />
      ) : eventsQ.isLoading ? (
        <div className="card p-6">
          <Spinner label="Loading audit events…" />
        </div>
      ) : sorted.length === 0 ? (
        <EmptyState>
          No audit events for tenant{" "}
          <span className="mx-1 font-mono">{tenant}</span>.
        </EmptyState>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/80 text-left text-[11px] uppercase tracking-wider text-slate-500">
                  <th className="px-3 py-2 font-medium">Seq</th>
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Actor</th>
                  <th className="px-3 py-2 font-medium">Event</th>
                  <th className="px-3 py-2 font-medium">Detail</th>
                  <th className="px-3 py-2 font-medium">Hash</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((e) => (
                  <tr
                    key={e.id}
                    className="border-b border-slate-800/60 hover:bg-slate-800/40"
                  >
                    <td className="px-3 py-1.5 font-mono text-xs text-slate-500">
                      {e.seq}
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5 text-xs text-slate-400">
                      {formatTime(e.ts)}
                    </td>
                    <td className="px-3 py-1.5">
                      <span className="chip">{e.actor}</span>
                    </td>
                    <td className="px-3 py-1.5 font-mono text-xs text-slate-200">
                      {e.event_type}
                    </td>
                    <td className="max-w-[420px] px-3 py-1.5">
                      <div className="truncate font-mono text-[11px] text-slate-500">
                        {summarizeData(e.data)}
                      </div>
                    </td>
                    <td className="px-3 py-1.5 font-mono text-[11px] text-slate-600">
                      {e.hash.slice(0, 12)}…
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
