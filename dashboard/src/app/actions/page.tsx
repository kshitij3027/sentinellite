"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Check, FlaskConical, ShieldX, X } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import {
  ActionStatusBadge,
  EmptyState,
  ErrorBox,
  Spinner,
} from "@/components/ui";
import { api } from "@/lib/api";
import { cn, prettyJson } from "@/lib/format";
import { useTenant } from "@/lib/tenant";
import type { Action } from "@/lib/types";

export default function ActionsPage() {
  const tenant = useTenant();
  const qc = useQueryClient();
  const [confirmTarget, setConfirmTarget] = useState<Action | null>(null);
  const [resultMsg, setResultMsg] = useState<Record<string, string>>({});

  const q = useQuery({
    queryKey: ["actions", tenant],
    queryFn: () => api.actions(),
    refetchInterval: 4000,
  });

  const approve = useMutation({
    mutationFn: ({ id, confirm }: { id: string; confirm: boolean }) =>
      api.approveAction(id, confirm),
    onSuccess: (action) => {
      // Irreversible actions return awaiting_confirm without a confirm=true.
      if (action.status === "awaiting_confirm") {
        setConfirmTarget(action);
      } else {
        const msg =
          (action.result && (action.result.message as string)) ||
          action.message ||
          `Action ${action.status}.`;
        setResultMsg((m) => ({ ...m, [action.id]: msg }));
        setConfirmTarget(null);
      }
      qc.invalidateQueries({ queryKey: ["actions", tenant] });
      qc.invalidateQueries({ queryKey: ["investigation", tenant] });
    },
  });

  const reject = useMutation({
    mutationFn: (id: string) => api.rejectAction(id),
    onSuccess: (action) => {
      setResultMsg((m) => ({ ...m, [action.id]: "Action rejected." }));
      qc.invalidateQueries({ queryKey: ["actions", tenant] });
    },
  });

  const actions = q.data?.actions ?? [];
  const pending = actions.filter(
    (a) => a.status === "staged" || a.status === "awaiting_confirm",
  );
  const recent = actions.filter(
    (a) => !["staged", "awaiting_confirm"].includes(a.status),
  );

  const busyId = approve.isPending
    ? approve.variables?.id
    : reject.isPending
      ? reject.variables
      : undefined;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Pending Actions</h1>
        <p className="text-sm text-slate-500">
          Human-in-the-loop response approvals for tenant{" "}
          <span className="font-mono text-slate-300">{tenant}</span>
        </p>
      </div>

      {q.isError ? (
        <ErrorBox error={q.error} />
      ) : q.isLoading ? (
        <div className="card p-6">
          <Spinner label="Loading actions…" />
        </div>
      ) : (
        <>
          <section className="space-y-3">
            <h2 className="text-xs uppercase tracking-wider text-slate-500">
              Awaiting approval ({pending.length})
            </h2>
            {pending.length === 0 ? (
              <EmptyState>No actions awaiting approval.</EmptyState>
            ) : (
              pending.map((a) => (
                <ActionCard
                  key={a.id}
                  action={a}
                  busy={busyId === a.id}
                  resultMsg={resultMsg[a.id]}
                  onApprove={() => {
                    if (a.requires_second_confirm) {
                      setConfirmTarget(a);
                    } else {
                      approve.mutate({ id: a.id, confirm: false });
                    }
                  }}
                  onReject={() => reject.mutate(a.id)}
                />
              ))
            )}
          </section>

          {recent.length > 0 && (
            <section className="space-y-3">
              <h2 className="text-xs uppercase tracking-wider text-slate-500">
                Recent ({recent.length})
              </h2>
              <div className="card divide-y divide-slate-800">
                {recent.map((a) => (
                  <div
                    key={a.id}
                    className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm text-slate-300">
                        {a.type}
                      </span>
                      <Link
                        href={`/investigations/${a.investigation_id}`}
                        className="text-[11px] text-sky-500 hover:underline"
                      >
                        {a.investigation_id}
                      </Link>
                    </div>
                    <div className="flex items-center gap-2">
                      {resultMsg[a.id] && (
                        <span className="text-[11px] text-slate-500">
                          {resultMsg[a.id]}
                        </span>
                      )}
                      <ActionStatusBadge status={a.status} />
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}
        </>
      )}

      {confirmTarget && (
        <ConfirmModal
          action={confirmTarget}
          busy={approve.isPending}
          onCancel={() => setConfirmTarget(null)}
          onConfirm={() =>
            approve.mutate({ id: confirmTarget.id, confirm: true })
          }
        />
      )}
    </div>
  );
}

function ActionCard({
  action,
  busy,
  resultMsg,
  onApprove,
  onReject,
}: {
  action: Action;
  busy: boolean;
  resultMsg?: string;
  onApprove: () => void;
  onReject: () => void;
}) {
  return (
    <div className="card p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-base font-semibold text-slate-100">
            {action.type}
          </span>
          <ActionStatusBadge status={action.status} />
          {action.dry_run && (
            <span className="badge border border-sky-500/40 bg-sky-500/10 text-sky-300">
              <FlaskConical className="h-3 w-3" /> dry-run
            </span>
          )}
          {action.requires_second_confirm && (
            <span className="badge border border-red-500/40 bg-red-500/10 text-red-300">
              <AlertTriangle className="h-3 w-3" /> irreversible
            </span>
          )}
        </div>
        <Link
          href={`/investigations/${action.investigation_id}`}
          className="text-[11px] text-sky-500 hover:underline"
        >
          {action.investigation_id}
        </Link>
      </div>

      <p className="mt-2 text-sm text-slate-300">{action.rationale}</p>

      <pre className="mt-2 overflow-x-auto rounded-md border border-slate-800 bg-[#0b0f17] p-2.5 font-mono text-[11px] text-slate-400">
        {prettyJson(action.params)}
      </pre>

      {resultMsg && (
        <div className="mt-2 rounded-md border border-emerald-500/30 bg-emerald-950/20 px-2.5 py-1.5 text-xs text-emerald-300">
          {resultMsg}
        </div>
      )}

      <div className="mt-3 flex items-center gap-2">
        <button
          onClick={onApprove}
          disabled={busy}
          className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/50 bg-emerald-500/15 px-3 py-1.5 text-sm font-medium text-emerald-200 hover:bg-emerald-500/25 disabled:opacity-50"
        >
          <Check className="h-4 w-4" />
          Approve
        </button>
        <button
          onClick={onReject}
          disabled={busy}
          className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800/60 px-3 py-1.5 text-sm font-medium text-slate-300 hover:bg-slate-700 disabled:opacity-50"
        >
          <X className="h-4 w-4" />
          Reject
        </button>
        {busy && <span className="text-xs text-slate-500">working…</span>}
      </div>
    </div>
  );
}

function ConfirmModal({
  action,
  busy,
  onCancel,
  onConfirm,
}: {
  action: Action;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="card w-full max-w-md border-red-500/40 bg-slate-900 p-5">
        <div className="flex items-center gap-2 text-red-300">
          <ShieldX className="h-5 w-5" />
          <h3 className="text-base font-semibold">Confirm irreversible action</h3>
        </div>
        <p className="mt-3 text-sm text-slate-300">
          {action.message ||
            `This will execute "${action.type}", which cannot be undone.`}
        </p>
        <pre className="mt-3 overflow-x-auto rounded-md border border-slate-800 bg-[#0b0f17] p-2.5 font-mono text-[11px] text-slate-400">
          {prettyJson(action.params)}
        </pre>
        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onCancel}
            disabled={busy}
            className="rounded-md border border-slate-700 bg-slate-800/60 px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-700 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={busy}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md border border-red-500/60 bg-red-500/20 px-3 py-1.5 text-sm font-medium text-red-200 hover:bg-red-500/30 disabled:opacity-50",
            )}
          >
            <AlertTriangle className="h-4 w-4" />
            {busy ? "Executing…" : "Confirm & execute"}
          </button>
        </div>
      </div>
    </div>
  );
}
