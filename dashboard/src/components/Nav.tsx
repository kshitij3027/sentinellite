"use client";

import { cn } from "@/lib/format";
import { Activity, ListChecks, Network, ScrollText, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { TenantSelector } from "./TenantSelector";

const LINKS = [
  { href: "/", label: "Alert Queue", icon: ShieldAlert, match: (p: string) => p === "/" },
  {
    href: "/investigations",
    label: "Investigations",
    icon: Network,
    match: (p: string) => p.startsWith("/investigations"),
  },
  {
    href: "/actions",
    label: "Actions",
    icon: ListChecks,
    match: (p: string) => p.startsWith("/actions"),
  },
  {
    href: "/audit",
    label: "Audit Log",
    icon: ScrollText,
    match: (p: string) => p.startsWith("/audit"),
  },
];

export function Nav() {
  const pathname = usePathname() || "/";
  return (
    <header className="sticky top-0 z-40 border-b border-slate-800 bg-[#0b0f17]/90 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-[1400px] items-center gap-6 px-4">
        <Link href="/" className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-red-500" />
          <span className="text-sm font-semibold tracking-tight text-slate-100">
            Sentinel<span className="text-red-500">Lite</span>
          </span>
          <span className="hidden rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-slate-400 sm:inline">
            Autonomous SOC
          </span>
        </Link>

        <nav className="flex items-center gap-1">
          {LINKS.map((l) => {
            const active = l.match(pathname);
            const Icon = l.icon;
            return (
              <Link
                key={l.href}
                href={l.href}
                className={cn(
                  "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition-colors",
                  active
                    ? "bg-slate-800 text-slate-100"
                    : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200",
                )}
              >
                <Icon className="h-4 w-4" />
                <span className="hidden md:inline">{l.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="ml-auto">
          <TenantSelector />
        </div>
      </div>
    </header>
  );
}
