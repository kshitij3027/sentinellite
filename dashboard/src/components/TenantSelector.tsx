"use client";

import { useQueryClient } from "@tanstack/react-query";
import { Building2 } from "lucide-react";
import { useEffect, useState } from "react";
import { setTenant, useTenant } from "@/lib/tenant";

// Text input for the active tenant, persisted in localStorage. Committing a
// new value updates the store and invalidates all queries so every view
// refetches with the new X-Tenant-Id header.
export function TenantSelector() {
  const tenant = useTenant();
  const [draft, setDraft] = useState(tenant);
  const qc = useQueryClient();

  // Keep the input in sync if the tenant changes elsewhere (e.g. hydration).
  useEffect(() => {
    setDraft(tenant);
  }, [tenant]);

  function commit() {
    const next = draft.trim() || "default";
    if (next !== tenant) {
      setTenant(next);
      qc.invalidateQueries();
    }
    setDraft(next);
  }

  return (
    <div className="flex items-center gap-2">
      <Building2 className="h-4 w-4 text-slate-500" />
      <div className="flex items-center overflow-hidden rounded-md border border-slate-700 bg-slate-900 focus-within:border-slate-500">
        <span className="border-r border-slate-700 bg-slate-800/60 px-2 py-1 text-[11px] uppercase tracking-wide text-slate-500">
          Tenant
        </span>
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              (e.target as HTMLInputElement).blur();
            }
          }}
          spellCheck={false}
          className="w-32 bg-transparent px-2 py-1 font-mono text-sm text-slate-100 outline-none placeholder:text-slate-600"
          placeholder="default"
          aria-label="Active tenant id"
        />
      </div>
    </div>
  );
}
