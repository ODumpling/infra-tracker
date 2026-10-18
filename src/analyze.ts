import type { Change, Finding, Listener, Snapshot } from "./types";

const PRIVATE = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, /^127\./, /^f[cd]/i, /^fe80/i, /^::1$/];

export const isPublicIp = (ip: string) => !PRIVATE.some((r) => r.test(ip));

export const hasPublicIp = (s: Snapshot) =>
  (s.addresses ?? []).some((a) => !a.iface.startsWith("docker") && !a.iface.startsWith("br-") && a.addrs.some((x) => isPublicIp(x.split("/")[0])));

/** Listening on every interface (not loopback / not a single specific address). */
export const isWildcard = (l: Listener) => l.addr === "0.0.0.0" || l.addr === "*" || l.addr === "::";

const NOISE_PORTS = new Set([53, 68, 323, 5353, 41641]);

/** Ports listening on all interfaces, merged across tcp/udp and v4/v6. */
export function exposedPorts(s: Snapshot): Listener[] {
  const byPort = new Map<number, Listener>();
  for (const l of s.listeners ?? []) {
    if (!isWildcard(l) || NOISE_PORTS.has(l.port) || (l.proto === "udp" && l.port > 32767)) continue;
    const o = byPort.get(l.port);
    if (!o) byPort.set(l.port, { ...l });
    else if (!o.proto.split("+").includes(l.proto)) o.proto = [o.proto, l.proto].sort().join("+");
  }
  return [...byPort.values()];
}

export function findings(s: Snapshot | null, error: { message: string } | null, scannedBefore: boolean): Finding[] {
  const f: Finding[] = [];
  if (error) f.push({ severity: "crit", text: `Last scan failed: ${error.message}` });
  if (!s) return f;

  const u = s.updates;
  if (u?.reboot_required) f.push({ severity: "warn", text: "Reboot required" });
  if (u?.pending) {
    const sec = u.security ? ` (${u.security} security)` : "";
    f.push({ severity: u.security || u.pending > 50 ? "warn" : "info", text: `${u.pending} pending updates${sec}` });
  }

  for (const d of s.disks ?? []) {
    const pct = d.size ? (d.used / d.size) * 100 : 0;
    if (pct > 95) f.push({ severity: "crit", text: `${d.mount} ${pct.toFixed(0)}% full` });
    else if (pct > 85) f.push({ severity: "warn", text: `${d.mount} ${pct.toFixed(0)}% full` });
  }
  const memPct = s.memory.total ? (s.memory.available / s.memory.total) * 100 : 100;
  if (memPct < 10) f.push({ severity: "warn", text: `Low memory: ${memPct.toFixed(0)}% available` });

  for (const d of s.smart ?? []) {
    if (d.passed === false) f.push({ severity: "crit", text: `SMART failing on ${d.device}` });
    if (d.temp && d.temp > 55) f.push({ severity: "warn", text: `${d.device} at ${d.temp}°C` });
  }

  const pub = hasPublicIp(s);
  const pve = s.proxmox;
  if (pve) {
    if (!pve.firewall_enabled) f.push({ severity: "info", text: "Proxmox firewall disabled" });
    if (pve.backup_jobs === 0) f.push({ severity: "crit", text: "No Proxmox backup jobs configured" });
    const vmids = new Set(pve.guests.map((g) => g.vmid));
    const orphans = pve.backups.filter((b) => !vmids.has(b.vmid));
    if (orphans.length) {
      const gb = orphans.reduce((a, b) => a + b.size, 0) / 1e9;
      f.push({ severity: "info", text: `${orphans.length} backups of deleted guests (${gb.toFixed(1)} GB)` });
    }
    for (const g of pve.guests) {
      if (g.onboot && g.status !== "running") f.push({ severity: "warn", text: `${g.type} ${g.vmid} ${g.name} is ${g.status} (onboot)` });
    }
  } else if (s.firewall && !s.firewall.active) {
    f.push({ severity: pub ? "crit" : "info", text: `Firewall (${s.firewall.kind}) inactive` });
  } else if (!s.firewall && pub) {
    f.push({ severity: "warn", text: "No firewall detected on public host" });
  }

  const exposed = exposedPorts(s).filter((l) => l.port !== 22);
  if (exposed.length) {
    const list = exposed.map((l) => `${l.port}${l.process ? ` (${l.process})` : ""}`).join(", ");
    f.push({ severity: pub && !s.firewall?.active ? "warn" : "info", text: `Listening on all interfaces: ${list}` });
  }

  for (const c of s.docker?.containers ?? []) {
    if (c.state !== "running") f.push({ severity: "warn", text: `Container ${c.name} is ${c.state}` });
    else if (/unhealthy/.test(c.status)) f.push({ severity: "warn", text: `Container ${c.name} unhealthy` });
  }
  if (s.docker && s.docker.containers.length === 0) f.push({ severity: "info", text: "Docker installed but no containers" });

  if (!s.tailscale) f.push({ severity: "info", text: "Not on tailnet" });
  else if (!s.tailscale.running) f.push({ severity: "warn", text: "Tailscale installed but not running" });

  for (const [k, v] of Object.entries(s.errors ?? {})) f.push({ severity: "info", text: `Collector error in ${k}: ${v}` });

  const age = Date.now() / 1000 - s.collected_at;
  if (scannedBefore && age > 7 * 86400) f.push({ severity: "info", text: `Data is ${Math.round(age / 86400)} days old` });

  const order = { crit: 0, warn: 1, info: 2 };
  return f.sort((a, b) => order[a.severity] - order[b.severity]);
}

function setDiff<T>(area: string, prev: T[], next: T[], key: (x: T) => string, label: (x: T) => string, out: Change[]) {
  const p = new Map(prev.map((x) => [key(x), x]));
  const n = new Map(next.map((x) => [key(x), x]));
  for (const [k, x] of n) if (!p.has(k)) out.push({ kind: "added", area, text: label(x) });
  for (const [k, x] of p) if (!n.has(k)) out.push({ kind: "removed", area, text: label(x) });
}

export function diff(prev: Snapshot | null, next: Snapshot | null): Change[] {
  if (!prev || !next) return [];
  const out: Change[] = [];

  const pg = prev.proxmox?.guests ?? [];
  const ng = next.proxmox?.guests ?? [];
  setDiff("guest", pg, ng, (g) => `${g.vmid}`, (g) => `${g.type} ${g.vmid} ${g.name}`, out);
  for (const g of ng) {
    const o = pg.find((x) => x.vmid === g.vmid);
    if (o && o.status !== g.status) out.push({ kind: "changed", area: "guest", text: `${g.vmid} ${g.name}: ${o.status} → ${g.status}` });
    if (o && (o.memory !== g.memory || o.cores !== g.cores))
      out.push({ kind: "changed", area: "guest", text: `${g.vmid} ${g.name}: resources changed` });
  }

  const pc = prev.docker?.containers ?? [];
  const nc = next.docker?.containers ?? [];
  setDiff("container", pc, nc, (c) => c.name, (c) => `${c.name} (${c.image})`, out);
  for (const c of nc) {
    const o = pc.find((x) => x.name === c.name);
    if (o && o.image !== c.image) out.push({ kind: "changed", area: "container", text: `${c.name}: ${o.image} → ${c.image}` });
    if (o && o.state !== c.state) out.push({ kind: "changed", area: "container", text: `${c.name}: ${o.state} → ${c.state}` });
  }

  const lk = (l: Listener) => `${l.proto}/${l.port}/${isWildcard(l) ? "*" : l.addr}`;
  const ll = (l: Listener) => `${l.proto} ${isWildcard(l) ? "*" : l.addr}:${l.port}${l.process ? ` ${l.process}` : ""}`;
  setDiff("port", prev.listeners ?? [], next.listeners ?? [], lk, ll, out);

  setDiff("service", prev.services ?? [], next.services ?? [], (s) => s, (s) => s, out);
  const us = (s: Snapshot) => Object.entries(s.user_services ?? {}).flatMap(([u, l]) => l.map((x) => `${u}:${x}`));
  setDiff("user service", us(prev), us(next), (s) => s, (s) => s, out);
  setDiff("tailscale serve", prev.tailscale?.serve ?? [], next.tailscale?.serve ?? [], (s) => s.url, (s) => `${s.url} → ${s.target}`, out);

  if (prev.os !== next.os) out.push({ kind: "changed", area: "os", text: `${prev.os} → ${next.os}` });
  if (prev.kernel !== next.kernel) out.push({ kind: "changed", area: "kernel", text: `${prev.kernel} → ${next.kernel}` });
  if (prev.proxmox?.version && prev.proxmox.version !== next.proxmox?.version)
    out.push({ kind: "changed", area: "proxmox", text: `${prev.proxmox.version} → ${next.proxmox?.version}` });
  if (next.uptime < prev.uptime) out.push({ kind: "changed", area: "uptime", text: "Host rebooted" });
  if (!!prev.firewall?.active !== !!next.firewall?.active)
    out.push({ kind: "changed", area: "firewall", text: next.firewall?.active ? "enabled" : "disabled" });

  return out;
}
