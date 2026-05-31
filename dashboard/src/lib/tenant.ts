"use client";

// A tiny external store for the active tenant id, persisted in localStorage.
// The API fetcher reads getTenant() at request time so every request carries
// the right X-Tenant-Id header, and React components subscribe via useTenant().

import { useSyncExternalStore } from "react";

const KEY = "sentinel.tenant";
export const DEFAULT_TENANT = "default";

let current = DEFAULT_TENANT;
let initialized = false;
const listeners = new Set<() => void>();

function ensureInit() {
  if (initialized || typeof window === "undefined") return;
  initialized = true;
  try {
    const stored = window.localStorage.getItem(KEY);
    if (stored && stored.trim()) current = stored.trim();
  } catch {
    /* ignore storage errors */
  }
}

export function getTenant(): string {
  ensureInit();
  return current || DEFAULT_TENANT;
}

export function setTenant(next: string) {
  const value = next.trim() || DEFAULT_TENANT;
  current = value;
  initialized = true;
  try {
    window.localStorage.setItem(KEY, value);
  } catch {
    /* ignore storage errors */
  }
  listeners.forEach((l) => l());
}

function subscribe(listener: () => void) {
  ensureInit();
  listeners.add(listener);
  return () => listeners.delete(listener);
}

// Reactive hook returning the current tenant id.
export function useTenant(): string {
  return useSyncExternalStore(
    subscribe,
    () => getTenant(),
    () => DEFAULT_TENANT,
  );
}
