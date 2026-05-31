// Display helpers shared across views.

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

// Relative + absolute timestamp. Returns "—" for missing input.
export function formatTime(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatRelative(ts?: string | null): string {
  if (!ts) return "";
  const d = new Date(ts).getTime();
  if (Number.isNaN(d)) return "";
  const diff = Date.now() - d;
  const s = Math.round(diff / 1000);
  if (Math.abs(s) < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (Math.abs(m) < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (Math.abs(h) < 24) return `${h}h ago`;
  const days = Math.round(h / 24);
  return `${days}d ago`;
}

// Map a severity label (or numeric score) to a tailwind text/border/bg family.
export function severityColor(label?: string | null): {
  text: string;
  bar: string;
  ring: string;
} {
  switch ((label || "").toLowerCase()) {
    case "critical":
      return { text: "text-red-400", bar: "bg-red-500", ring: "ring-red-500/40" };
    case "high":
      return { text: "text-orange-400", bar: "bg-orange-500", ring: "ring-orange-500/40" };
    case "medium":
      return { text: "text-amber-400", bar: "bg-amber-500", ring: "ring-amber-500/40" };
    case "low":
      return { text: "text-blue-400", bar: "bg-blue-500", ring: "ring-blue-500/40" };
    default:
      return { text: "text-slate-400", bar: "bg-slate-500", ring: "ring-slate-500/30" };
  }
}

// Bucket a 0-100 score into a severity-like band for bar coloring.
export function scoreColor(score?: number | null): string {
  if (score == null) return "bg-slate-600";
  if (score >= 80) return "bg-red-500";
  if (score >= 60) return "bg-orange-500";
  if (score >= 40) return "bg-amber-500";
  if (score >= 20) return "bg-blue-500";
  return "bg-slate-500";
}

// Stable color for graph node labels (security-ops palette).
export function nodeColor(label: string): string {
  switch (label) {
    case "Alert":
      return "#ef4444"; // red — the events
    case "Identity":
      return "#a78bfa"; // violet
    case "IP":
      return "#38bdf8"; // sky
    case "Asset":
      return "#34d399"; // emerald
    case "Process":
      return "#fbbf24"; // amber
    case "Package":
      return "#f472b6"; // pink
    case "Repository":
      return "#22d3ee"; // cyan
    case "CloudResource":
      return "#fb923c"; // orange
    default:
      return "#94a3b8"; // slate
  }
}

export function prettyJson(obj: unknown): string {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}
