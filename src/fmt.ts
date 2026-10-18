export const esc = (v: unknown) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export function bytes(n?: number | null) {
  if (!n) return "0";
  const u = ["B", "K", "M", "G", "T"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) (n /= 1024), i++;
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)}${u[i]}`;
}

export function duration(sec?: number | null) {
  if (!sec) return "–";
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

export function ago(ts?: number | null) {
  if (!ts) return "never";
  const s = Date.now() / 1000 - ts;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const date = (ts: number) => new Date(ts * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

export const pct = (used: number, total: number) => (total ? Math.round((used / total) * 100) : 0);
