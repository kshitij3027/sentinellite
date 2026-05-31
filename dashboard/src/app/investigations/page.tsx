"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, Layers } from "lucide-react";
import Link from "next/link";
import {
  EmptyState,
  ErrorBox,
  InvestigationStatusBadge,
  ScoreBar,
  Spinner,
} from "@/components/ui";
import { api } from "@/lib/api";
import { formatRelative } from "@/lib/format";
import { useTenant } from "@/lib/tenant";

export default function InvestigationsPage() {
  const tenant = useTenant();
  const q = useQuery({
    queryKey: ["investigations", tenant, "list"],
    queryFn: () => api.investigations({ limit: 50 }),
    refetchInterval: 4000,
  });

  const investigations = q.data?.investigations ?? [];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Investigations</h1>
        <p className="text-sm text-slate-500">
          Correlated multi-stage incidents for tenant{" "}
          <span className="font-mono text-slate-300">{tenant}</span>
        </p>
      </div>

      {q.isError ? (
        <ErrorBox error={q.error} />
      ) : q.isLoading ? (
        <div className="card p-6">
          <Spinner label="Loading investigations…" />
        </div>
      ) : investigations.length === 0 ? (
        <EmptyState>
          No investigations for tenant{" "}
          <span className="mx-1 font-mono">{tenant}</span>. Try{" "}
          <span className="mx-1 font-mono">teampcp6</span>.
        </EmptyState>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {investigations.map((inv) => (
            <Link
              key={inv.id}
              href={`/investigations/${inv.id}`}
              className="card group block p-4 transition-colors hover:border-slate-600 hover:bg-slate-900"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <InvestigationStatusBadge status={inv.status} />
                  <span className="inline-flex items-center gap-1 text-xs text-slate-500">
                    <Layers className="h-3.5 w-3.5" />
                    {inv.stage_count} stages
                  </span>
                </div>
                <ArrowUpRight className="h-4 w-4 text-slate-600 transition-colors group-hover:text-slate-300" />
              </div>

              <p className="mt-3 line-clamp-3 text-sm leading-relaxed text-slate-200">
                {inv.summary}
              </p>

              <div className="mt-4 space-y-1.5">
                <ScoreBar label="Severity" value={inv.scores?.severity} />
                <ScoreBar label="Confidence" value={inv.scores?.confidence} />
                <ScoreBar label="Priority" value={inv.scores?.priority} />
              </div>

              <div className="mt-3 flex items-center justify-between text-[11px] text-slate-600">
                <span className="font-mono">{inv.id}</span>
                <span>updated {formatRelative(inv.updated_at)}</span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
