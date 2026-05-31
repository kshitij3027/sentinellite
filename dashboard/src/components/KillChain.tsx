"use client";

import { Crosshair } from "lucide-react";
import type { KillChainStep } from "@/lib/types";

export function KillChain({ steps }: { steps: KillChainStep[] }) {
  const sorted = [...steps].sort((a, b) => a.t_offset_s - b.t_offset_s);
  return (
    <div className="card p-4">
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-200">
        <Crosshair className="h-4 w-4 text-red-400" />
        Kill Chain
        <span className="text-xs font-normal text-slate-500">
          {sorted.length} stages
        </span>
      </h2>
      <ol className="relative space-y-4 pl-6">
        {/* Vertical spine. */}
        <span className="absolute left-[7px] top-1 h-[calc(100%-0.5rem)] w-px bg-slate-700" />
        {sorted.map((step, i) => (
          <li key={`${step.mitre}-${i}`} className="relative">
            <span className="absolute -left-[22px] top-1 flex h-3.5 w-3.5 items-center justify-center rounded-full border-2 border-red-500 bg-[#0b0f17]">
              <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
            </span>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-amber-300">
                t+{step.t_offset_s}s
              </span>
              <span className="text-sm font-medium text-slate-100">
                {step.stage}
              </span>
              <span
                className="chip border-violet-500/40 bg-violet-500/10 text-violet-300"
                title={step.mitre_name}
              >
                {step.mitre}
              </span>
              <span className="text-[11px] text-slate-500">{step.mitre_name}</span>
            </div>
            <p className="mt-1 text-sm text-slate-300">{step.summary}</p>
            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500">
              {step.evidence?.length > 0 && (
                <span>
                  {step.evidence.length} evidence alert
                  {step.evidence.length === 1 ? "" : "s"}
                </span>
              )}
              {step.entities?.length > 0 && (
                <span className="flex flex-wrap gap-1">
                  {step.entities.map((e) => (
                    <span key={e} className="chip">
                      {e}
                    </span>
                  ))}
                </span>
              )}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
