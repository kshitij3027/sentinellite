"use client";

// Lightweight shadcn-style primitives, hand-rolled with tailwind.

import { cn, scoreColor } from "@/lib/format";
import type {
  ActionStatus,
  AlertStatus,
  InvestigationStatus,
} from "@/lib/types";

export function ScoreBar({
  label,
  value,
}: {
  label: string;
  value?: number | null;
}) {
  const has = value != null;
  return (
    <div className="flex w-full items-center gap-2">
      <span className="w-[68px] shrink-0 text-[11px] uppercase tracking-wide text-slate-500">
        {label}
      </span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-800">
        {has && (
          <div
            className={cn("h-full rounded-full", scoreColor(value))}
            style={{ width: `${Math.max(2, Math.min(100, value ?? 0))}%` }}
          />
        )}
      </div>
      <span
        className={cn(
          "w-8 shrink-0 text-right font-mono text-xs",
          has ? "text-slate-200" : "text-slate-600",
        )}
      >
        {has ? value : "—"}
      </span>
    </div>
  );
}

// Compact inline metric for tables: colored number with a tiny bar underneath.
export function ScoreCell({ value }: { value?: number | null }) {
  if (value == null) {
    return <span className="font-mono text-sm text-slate-600">—</span>;
  }
  return (
    <div className="min-w-[44px]">
      <div className="font-mono text-sm text-slate-200">{value}</div>
      <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-slate-800">
        <div
          className={cn("h-full rounded-full", scoreColor(value))}
          style={{ width: `${Math.max(4, Math.min(100, value))}%` }}
        />
      </div>
    </div>
  );
}

const ALERT_STATUS_STYLE: Record<AlertStatus, string> = {
  escalated: "bg-red-500/15 text-red-300 border border-red-500/40",
  auto_closed: "bg-slate-700/40 text-slate-400 border border-slate-700",
  new: "bg-amber-500/15 text-amber-300 border border-amber-500/40",
  triaged: "bg-blue-500/15 text-blue-300 border border-blue-500/40",
};

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  return (
    <span className={cn("badge", ALERT_STATUS_STYLE[status] ?? ALERT_STATUS_STYLE.new)}>
      {status.replace("_", " ")}
    </span>
  );
}

const INV_STATUS_STYLE: Record<InvestigationStatus, string> = {
  running: "bg-sky-500/15 text-sky-300 border border-sky-500/40",
  awaiting_approval: "bg-amber-500/15 text-amber-300 border border-amber-500/40",
  approved: "bg-emerald-500/15 text-emerald-300 border border-emerald-500/40",
  rejected: "bg-red-500/15 text-red-300 border border-red-500/40",
  closed: "bg-slate-700/40 text-slate-400 border border-slate-700",
};

export function InvestigationStatusBadge({
  status,
}: {
  status: InvestigationStatus;
}) {
  return (
    <span className={cn("badge", INV_STATUS_STYLE[status] ?? INV_STATUS_STYLE.running)}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

const ACTION_STATUS_STYLE: Record<ActionStatus, string> = {
  staged: "bg-amber-500/15 text-amber-300 border border-amber-500/40",
  awaiting_confirm: "bg-orange-500/15 text-orange-300 border border-orange-500/40",
  approved: "bg-emerald-500/15 text-emerald-300 border border-emerald-500/40",
  executed: "bg-emerald-500/15 text-emerald-300 border border-emerald-500/40",
  rejected: "bg-red-500/15 text-red-300 border border-red-500/40",
  failed: "bg-red-500/15 text-red-300 border border-red-500/40",
  expired: "bg-slate-700/40 text-slate-400 border border-slate-700",
};

export function ActionStatusBadge({ status }: { status: ActionStatus }) {
  return (
    <span className={cn("badge", ACTION_STATUS_STYLE[status] ?? ACTION_STATUS_STYLE.staged)}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: React.ReactNode;
  accent?: string;
}) {
  return (
    <div className="card px-4 py-3">
      <div className="text-[11px] uppercase tracking-wider text-slate-500">
        {label}
      </div>
      <div className={cn("mt-1 text-2xl font-semibold tabular-nums", accent ?? "text-slate-100")}>
        {value}
      </div>
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-slate-500">
      <span className="h-3 w-3 animate-spin rounded-full border-2 border-slate-600 border-t-slate-300" />
      {label ?? "Loading…"}
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="card border-red-500/40 bg-red-950/30 p-4 text-sm text-red-300">
      <div className="font-medium">Failed to load data</div>
      <div className="mt-1 break-all font-mono text-xs text-red-400/80">{msg}</div>
      <div className="mt-2 text-xs text-slate-400">
        Check that the API is reachable and the tenant id is correct.
      </div>
    </div>
  );
}

export function EmptyState({ children }: { children: React.ReactNode }) {
  return (
    <div className="card flex items-center justify-center p-10 text-sm text-slate-500">
      {children}
    </div>
  );
}
