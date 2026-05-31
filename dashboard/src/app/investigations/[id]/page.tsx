"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Database, FileWarning, ListChecks } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { AgentTimeline } from "@/components/AgentTimeline";
import { AttackGraph } from "@/components/AttackGraph";
import { KillChain } from "@/components/KillChain";
import {
  ActionStatusBadge,
  ErrorBox,
  InvestigationStatusBadge,
  ScoreBar,
  Spinner,
} from "@/components/ui";
import { api } from "@/lib/api";
import { formatTime } from "@/lib/format";
import { useTenant } from "@/lib/tenant";

export default function InvestigationDetailPage() {
  const params = useParams();
  const id = String(params.id);
  const tenant = useTenant();

  const q = useQuery({
    queryKey: ["investigation", tenant, id],
    queryFn: () => api.investigation(id),
    refetchInterval: 5000,
  });

  if (q.isError) {
    return (
      <div className="space-y-4">
        <BackLink />
        <ErrorBox error={q.error} />
      </div>
    );
  }
  if (q.isLoading || !q.data) {
    return (
      <div className="space-y-4">
        <BackLink />
        <div className="card p-6">
          <Spinner label="Loading investigation…" />
        </div>
      </div>
    );
  }

  const inv = q.data;
  const triggerAlert =
    inv.alerts.find((a) => a.id === inv.trigger_alert_id) ?? null;
  const pendingActions = inv.actions.filter(
    (a) => a.status === "staged" || a.status === "awaiting_confirm",
  );

  return (
    <div className="space-y-5">
      <BackLink />

      {/* Header: summary, status, scores. */}
      <div className="card p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            <InvestigationStatusBadge status={inv.status} />
            <span className="font-mono text-xs text-slate-500">{inv.id}</span>
          </div>
          <span className="text-xs text-slate-500">
            created {formatTime(inv.created_at)}
          </span>
        </div>
        <h1 className="mt-3 text-lg font-semibold leading-snug text-slate-100">
          {inv.summary}
        </h1>

        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <div className="space-y-1.5">
            <ScoreBar label="Severity" value={inv.scores?.severity} />
            <ScoreBar label="Confidence" value={inv.scores?.confidence} />
            <ScoreBar label="Priority" value={inv.scores?.priority} />
          </div>
          {/* Trigger alert callout — answers "which alert started this?". */}
          {triggerAlert && (
            <div className="rounded-md border border-red-500/30 bg-red-950/20 p-3">
              <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-red-400/80">
                <FileWarning className="h-3.5 w-3.5" />
                Triggered by
              </div>
              <div className="mt-1 text-sm text-slate-100">
                {triggerAlert.title}
              </div>
              <div className="mt-0.5 text-[11px] text-slate-500">
                <span className="chip mr-1">{triggerAlert.source}</span>
                {triggerAlert.actor_identity}
                {triggerAlert.source_ip ? ` · ${triggerAlert.source_ip}` : ""}
              </div>
            </div>
          )}
        </div>

        {pendingActions.length > 0 && (
          <Link
            href="/actions"
            className="mt-4 inline-flex items-center gap-1.5 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-sm text-amber-200 hover:bg-amber-500/20"
          >
            <ListChecks className="h-4 w-4" />
            {pendingActions.length} action
            {pendingActions.length === 1 ? "" : "s"} awaiting approval
          </Link>
        )}
      </div>

      {/* Graph + kill chain side by side on wide screens. */}
      <div className="grid gap-5 xl:grid-cols-2">
        <AttackGraph investigationId={id} />
        <KillChain steps={inv.kill_chain} />
      </div>

      {/* Agent timeline + provenance. */}
      <div className="grid gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <AgentTimeline investigationId={id} findings={inv.findings} />
        </div>
        <div className="space-y-5">
          <ProvenancePanel
            sources={inv.data_provenance?.sources ?? []}
            datasets={inv.data_provenance?.datasets ?? []}
            scenario={inv.data_provenance?.scenario}
          />
          {inv.actions.length > 0 && (
            <div className="card p-4">
              <h2 className="mb-3 text-sm font-semibold text-slate-200">
                Response Actions
              </h2>
              <div className="space-y-2">
                {inv.actions.map((a) => (
                  <div
                    key={a.id}
                    className="flex items-center justify-between gap-2 rounded border border-slate-800 px-2.5 py-1.5 text-sm"
                  >
                    <span className="font-mono text-xs text-slate-300">
                      {a.type}
                    </span>
                    <ActionStatusBadge status={a.status} />
                  </div>
                ))}
              </div>
              <Link
                href="/actions"
                className="mt-3 inline-block text-xs text-sky-400 hover:underline"
              >
                Manage in Actions →
              </Link>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ProvenancePanel({
  sources,
  datasets,
  scenario,
}: {
  sources: string[];
  datasets: string[];
  scenario?: string | null;
}) {
  return (
    <div className="card p-4">
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-200">
        <Database className="h-4 w-4 text-emerald-400" />
        Data Provenance
      </h2>
      {scenario && (
        <div className="mb-3 text-[11px] text-slate-500">
          Scenario <span className="chip ml-1">{scenario}</span>
        </div>
      )}
      <div className="mb-3">
        <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">
          Sources
        </div>
        <div className="flex flex-wrap gap-1">
          {sources.map((s) => (
            <span key={s} className="chip">
              {s}
            </span>
          ))}
        </div>
      </div>
      <div>
        <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">
          Datasets cited
        </div>
        <ul className="space-y-1">
          {datasets.map((d) => (
            <li
              key={d}
              className="rounded border border-slate-800 bg-slate-900/60 px-2 py-1 text-xs text-slate-300"
            >
              {d}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      href="/investigations"
      className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200"
    >
      <ArrowLeft className="h-4 w-4" />
      All investigations
    </Link>
  );
}
