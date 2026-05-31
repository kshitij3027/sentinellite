"use client";

// Thin API client for the SentinelLite backend. Every request sends the active
// tenant id as X-Tenant-Id. The browser (on the host) talks to the API at
// NEXT_PUBLIC_API_BASE, defaulting to http://localhost:8000.

import { getTenant } from "./tenant";
import type {
  Action,
  ActionsResponse,
  AlertDetail,
  AlertsResponse,
  AuditResponse,
  AuditVerify,
  InvestigationDetail,
  InvestigationGraph,
  InvestigationsResponse,
} from "./types";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "X-Tenant-Id": getTenant(),
      ...(init?.headers || {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status} ${res.statusText} on ${path}: ${text.slice(0, 200)}`);
  }
  return (await res.json()) as T;
}

function qs(params: Record<string, string | number | undefined>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "" && v !== null) sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

export const api = {
  alerts: (params: { status?: string; source?: string; limit?: number } = {}) =>
    apiFetch<AlertsResponse>(`/alerts${qs({ limit: 100, ...params })}`),
  alert: (id: string) => apiFetch<AlertDetail>(`/alerts/${id}`),

  investigations: (params: { status?: string; limit?: number } = {}) =>
    apiFetch<InvestigationsResponse>(`/investigations${qs({ limit: 50, ...params })}`),
  investigation: (id: string) =>
    apiFetch<InvestigationDetail>(`/investigations/${id}`),
  investigationGraph: (id: string) =>
    apiFetch<InvestigationGraph>(`/investigations/${id}/graph`),

  actions: (params: { status?: string; investigation_id?: string } = {}) =>
    apiFetch<ActionsResponse>(`/actions${qs(params)}`),
  approveAction: (id: string, confirm: boolean) =>
    apiFetch<Action>(`/actions/${id}/approve${qs({ confirm: String(confirm) })}`, {
      method: "POST",
    }),
  rejectAction: (id: string) =>
    apiFetch<Action>(`/actions/${id}/reject`, { method: "POST" }),

  audit: (params: { limit?: number } = {}) =>
    apiFetch<AuditResponse>(`/audit${qs({ limit: 200, ...params })}`),
  auditVerify: () => apiFetch<AuditVerify>(`/audit/verify`),
};

// Build a tenant-aware EventSource URL for the SSE stream. EventSource cannot
// set custom headers, so the tenant is passed as a query param too; the native
// header path is preferred but we include this as a best-effort fallback.
export function streamUrl(investigationId: string): string {
  const tenant = getTenant();
  return `${API_BASE}/investigations/${investigationId}/stream${qs({
    tenant_id: tenant,
  })}`;
}
