import { getVersion } from "@tauri-apps/api/app";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { api } from "./api";
import { diff, exposedPorts, findings, isWildcard } from "./analyze";
import { ago, bytes, date, duration, esc, pct } from "./fmt";
import { toMarkdown } from "./markdown";
import type { Change, Config, Finding, Host, HostState, Snapshot } from "./types";

let config: Config;
let state: Record<string, HostState> = {};
let notes: Record<string, string> = {};
let view = "overview"; // "overview" | "settings" | host id
const scanning = new Set<string>();
const compareWith: Record<string, number | undefined> = {};
const compareCache: Record<string, Snapshot> = {};
/** Local time (s) of each host's last scan attempt, for monitoring. */
const lastScan: Record<string, number> = {};
/** Add-host form: address/user → probe → editable host prefilled from the scan. */
let draft: { addr: string; user: string; probing: boolean; snapshot?: Snapshot; host?: Host } = { addr: "", user: "", probing: false };
let version = "";
/** Pending update from GitHub releases (latest.json); `progress` set while downloading. */
let update: Update | null = null;
let progress: string | undefined;

const $app = document.querySelector<HTMLDivElement>("#app")!;

// ---------- helpers ----------

const MONITOR_OPTIONS = [5, 10, 15, 30, 60];
const minLabel = (m: number) => (m === 0 ? "Off" : m < 60 ? `${m} min` : `${m / 60} h`);
/** Effective monitoring interval in minutes (0 = off). */
const monitorMin = (h: Host) => h.monitor_min ?? config.scan_interval_min;
const monitorSelect = (attrs: string, value: number | null | undefined) =>
  `<select ${attrs}><option value="" ${value == null ? "selected" : ""}>Default (${minLabel(config.scan_interval_min)})</option>${[0, ...MONITOR_OPTIONS]
    .map((m) => `<option value="${m}" ${value === m ? "selected" : ""}>${minLabel(m)}</option>`).join("")}</select>`;

const hostFindings = (id: string) => {
  const st = state[id];
  return findings(st?.latest ?? null, st?.error ?? null, true);
};

function status(id: string): "ok" | "warn" | "crit" | "none" {
  const st = state[id];
  if (!st?.latest && !st?.error) return "none";
  const f = hostFindings(id);
  return f.some((x) => x.severity === "crit") ? "crit" : f.some((x) => x.severity === "warn") ? "warn" : "ok";
}

function toast(msg: string, error = false) {
  const el = document.createElement("div");
  el.className = `toast${error ? " error" : ""}`;
  el.textContent = msg;
  document.body.append(el);
  setTimeout(() => el.remove(), error ? 6000 : 3000);
}

const bar = (used: number, total: number, label = "") => {
  const p = pct(used, total);
  return `<div class="bar ${p > 90 ? "crit" : p > 80 ? "warn" : ""}" title="${esc(label)}"><i style="width:${p}%"></i></div>`;
};

const sevIcon = { crit: "●", warn: "▲", info: "○" };
const findingList = (f: Finding[]) =>
  f.length ? `<ul class="findings">${f.map((x) => `<li class="${x.severity}"><span>${sevIcon[x.severity]}</span>${esc(x.text)}</li>`).join("")}</ul>` : `<p class="muted">No findings</p>`;

const changeList = (c: Change[]) =>
  c.length ? `<ul class="changes">${c.map((x) => `<li class="${x.kind}"><span>${x.kind === "added" ? "+" : x.kind === "removed" ? "−" : "~"}</span><em>${esc(x.area)}</em> ${esc(x.text)}</li>`).join("")}</ul>` : `<p class="muted">No changes</p>`;

const card = (title: string, body: string, cls = "") => `<section class="card ${cls}"><h3>${title}</h3>${body}</section>`;

const tbl = (head: string[], rows: string[][], cls = "") =>
  rows.length ? `<table class="${cls}"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>` : `<p class="muted">None</p>`;

/** Configured host matching a Proxmox guest (by name or IP). */
const hostForGuest = (name: string, ip?: string | null) =>
  config.hosts.find((h) => h.name === name || h.id === name || (ip && h.ssh.endsWith(`@${ip}`)) || h.ssh === ip);

const shortOs = (os: string) => os.replace(/\s*(LTS|GNU\/Linux)\b.*$/, "").replace(/\s*\(.*\)$/, "");

/** Prefill a host entry from a probe snapshot: name/id from hostname, parent + VM id from any Proxmox host listing it as a guest. */
function inferHost(s: Snapshot, ssh: string, addr: string): Host {
  const name = s.hostname.split(".")[0] || addr;
  const base = name.toLowerCase().replace(/[^a-z0-9_.-]+/g, "-").replace(/^[-.]+|-+$/g, "") || "host";
  let id = base;
  for (let i = 2; config.hosts.some((h) => h.id === id); i++) id = `${base}-${i}`;
  const ips = new Set([addr, ...(s.addresses ?? []).flatMap((a) => a.addrs.map((x) => x.split("/")[0]))]);
  let parent: string | null = null, guest = "";
  for (const h of config.hosts) {
    const g = state[h.id]?.latest?.proxmox?.guests.find((g) => (g.ip && ips.has(g.ip)) || g.name === name);
    if (g) { parent = h.id; guest = `${g.type === "lxc" ? "CT" : "VM"} ${g.vmid}`; break; }
  }
  const kind = s.proxmox ? "Proxmox host" : s.docker?.containers.length ? `Docker · ${shortOs(s.os)}` : shortOs(s.os);
  return { id, name, ssh, parent, role: [guest, kind].filter(Boolean).join(" · ") };
}

// ---------- render ----------

function render() {
  const roots = config.hosts.filter((h) => !h.parent || !config.hosts.some((p) => p.id === h.parent));
  const children = (id: string) => config.hosts.filter((h) => h.parent === id);
  const navItem = (h: Host, depth: number): string =>
    `<button class="nav host ${view === h.id ? "active" : ""}" data-view="${esc(h.id)}" style="--d:${depth}">
       <span class="dot ${scanning.has(h.id) ? "spin" : status(h.id)}"></span>
       <span class="name">${esc(h.name)}</span>
       <span class="age">${scanning.has(h.id) ? "…" : ago(state[h.id]?.latest?.collected_at)}</span>
     </button>` + children(h.id).map((c) => navItem(c, depth + 1)).join("");

  $app.innerHTML = `
    <aside>
      <div class="brand">Infra Tracker</div>
      <button class="nav ${view === "overview" ? "active" : ""}" data-view="overview">Overview</button>
      <div class="navlabel">Hosts</div>
      ${roots.map((h) => navItem(h, 0)).join("")}
      <button class="nav add ${view === "add" ? "active" : ""}" data-view="add">+ Add host</button>
      <div class="spacer"></div>
      ${update ? `<button class="nav update" data-action="install-update" ${progress ? "disabled" : ""}>${progress ?? `Update to ${esc(update.version)}`}</button>` : ""}
      <button class="nav ${view === "settings" ? "active" : ""}" data-view="settings">Settings</button>
    </aside>
    <main>
      <header>
        <h1>${view === "overview" ? "Overview" : view === "settings" ? "Settings" : view === "add" ? "Add host" : esc(config.hosts.find((h) => h.id === view)?.name)}</h1>
        <div class="actions">
          <button data-action="export">Export markdown</button>
          <button class="primary" data-action="scan-all" ${scanning.size ? "disabled" : ""}>${scanning.size ? `Scanning ${scanning.size}…` : "Scan all"}</button>
        </div>
      </header>
      <div class="content">${view === "overview" ? overview() : view === "settings" ? settings() : view === "add" ? addView() : hostView(view)}</div>
    </main>`;
}

function overview() {
  const cards = config.hosts.map((h) => {
    const st = state[h.id];
    const s = st?.latest;
    const f = hostFindings(h.id);
    const root = s?.disks?.find((d) => d.mount === "/");
    const counts = s ? [
      s.proxmox && `${s.proxmox.guests.length} guests`,
      s.docker && `${s.docker.containers.length} containers`,
      `${exposedPorts(s).length} exposed ports`,
    ].filter(Boolean).join(" · ") : "";
    return `<button class="hostcard ${status(h.id)}" data-view="${esc(h.id)}">
      <div class="hc-head"><span class="dot ${scanning.has(h.id) ? "spin" : status(h.id)}"></span><b>${esc(h.name)}</b><span class="muted">${esc(h.role ?? "")}</span></div>
      ${s ? `
        <div class="muted small">${esc(s.os)} · up ${duration(s.uptime)}</div>
        <div class="meters">
          <label>CPU <span>${s.load[0].toFixed(2)} / ${s.cpu.count}</span></label>${bar(s.load[0], s.cpu.count)}
          <label>RAM <span>${bytes(s.memory.total - s.memory.available)} / ${bytes(s.memory.total)}</span></label>${bar(s.memory.total - s.memory.available, s.memory.total)}
          ${root ? `<label>Disk <span>${bytes(root.used)} / ${bytes(root.size)}</span></label>${bar(root.used, root.size)}` : ""}
        </div>
        <div class="small">${counts}</div>` : `<p class="muted">${st?.error ? esc(st.error.message) : "Not scanned yet"}</p>`}
      <div class="hc-foot">
        ${f.filter((x) => x.severity === "crit").length ? `<span class="pill crit">${f.filter((x) => x.severity === "crit").length} critical</span>` : ""}
        ${f.filter((x) => x.severity === "warn").length ? `<span class="pill warn">${f.filter((x) => x.severity === "warn").length} warnings</span>` : ""}
        <span class="muted small">${monitorMin(h) ? `every ${minLabel(monitorMin(h))} · ` : ""}${ago(s?.collected_at)}</span>
      </div>
    </button>`;
  });

  const endpoints: string[][] = [];
  for (const h of config.hosts) {
    const s = state[h.id]?.latest;
    if (!s) continue;
    for (const t of s.tailscale?.serve ?? []) endpoints.push([esc(h.name), `<code>${esc(t.url)}</code>`, esc(t.target), `<span class="pill ok">tailnet</span>`]);
    for (const l of exposedPorts(s).filter((l) => l.port !== 22)) endpoints.push([esc(h.name), `<code>${l.proto}/${l.port}</code>`, esc(l.process), `<span class="pill warn">all interfaces</span>`]);
  }

  const allFindings = config.hosts.flatMap((h) => hostFindings(h.id).filter((f) => f.severity !== "info").map((f) => ({ ...f, text: `${h.name}: ${f.text}` })));

  return `
    <div class="hostgrid">${cards.join("")}</div>
    <div class="grid2">
      ${card("Attention", findingList(allFindings))}
      ${card(`Exposed endpoints <span class="muted">excluding ssh</span>`, tbl(["Host", "Endpoint", "Backend", "Exposure"], endpoints))}
    </div>`;
}

function hostView(id: string) {
  const h = config.hosts.find((x) => x.id === id);
  if (!h) return `<p>Unknown host</p>`;
  const st = state[id] ?? { latest: null, previous: null, error: null, history: [] };
  const s = st.latest;
  const cmpTs = compareWith[id];
  const base = cmpTs ? compareCache[`${id}:${cmpTs}`] ?? null : st.previous;

  const head = `
    <div class="hosthead">
      <div>
        <div class="muted">${esc(h.role ?? "")} · <code>ssh ${esc(h.ssh)}</code></div>
        <div class="muted small">${s ? `Scanned ${date(s.collected_at)} · ${st.history.length} snapshots` : "Never scanned"}</div>
      </div>
      <label class="monitor muted small">Monitor ${monitorSelect(`data-action="monitor" data-id="${esc(id)}"`, h.monitor_min)}</label>
      <button class="primary" data-action="scan" data-id="${esc(id)}" ${scanning.has(id) ? "disabled" : ""}>${scanning.has(id) ? "Scanning…" : "Scan now"}</button>
    </div>
    ${st.error ? `<div class="banner crit">Last scan failed ${ago(st.error.at)}: ${esc(st.error.message)}</div>` : ""}`;

  if (!s) return head + card("Notes", notesBox(id));

  const sections: string[] = [];

  sections.push(card("System", `
    <dl>
      <dt>OS</dt><dd>${esc(s.os)}</dd>
      <dt>Kernel</dt><dd>${esc(s.kernel)}</dd>
      <dt>CPU</dt><dd>${s.cpu.count}× ${esc(s.cpu.model)}</dd>
      <dt>Uptime</dt><dd>${duration(s.uptime)} · load ${s.load.map((l) => l.toFixed(2)).join(" ")}</dd>
      <dt>Memory</dt><dd>${bytes(s.memory.total - s.memory.available)} / ${bytes(s.memory.total)}${s.memory.swap_total ? ` · swap ${bytes(s.memory.swap_total)}` : " · no swap"}${bar(s.memory.total - s.memory.available, s.memory.total)}</dd>
      ${(s.disks ?? []).map((d) => `<dt>${esc(d.mount)}</dt><dd>${bytes(d.used)} / ${bytes(d.size)} <span class="muted">${esc(d.fstype)}</span>${bar(d.used, d.size)}</dd>`).join("")}
      ${(s.smart ?? []).map((d) => `<dt>${esc(d.device)}</dt><dd>${esc(d.model ?? "")} · SMART ${d.passed ? "OK" : d.passed === false ? "<b class=crit>FAIL</b>" : "?"} · ${d.power_on_hours ?? "?"}h · ${d.temp ?? "?"}°C</dd>`).join("")}
      <dt>Updates</dt><dd>${s.updates?.pending ?? "?"} pending${s.updates?.security ? ` (${s.updates.security} security)` : ""}${s.updates?.reboot_required ? ` · <b class="warn">reboot required</b>` : ""}</dd>
    </dl>`));

  sections.push(card("Findings", findingList(findings(s, st.error, true))));

  const options = st.history.slice(1).map((t) => `<option value="${t}" ${t === cmpTs ? "selected" : ""}>${date(t)}</option>`).join("");
  sections.push(card(`Changes <select data-action="compare" data-id="${esc(id)}"><option value="">vs previous</option>${options}</select>`,
    base ? `<p class="muted small">Since ${date(base.collected_at)}</p>${changeList(diff(base, s))}` : `<p class="muted">Need two scans to compare</p>`));

  sections.push(card("Network", `
    <dl>${(s.addresses ?? []).filter((a) => a.addrs.length).map((a) => `<dt>${esc(a.iface)}</dt><dd>${a.addrs.map((x) => `<code>${esc(x)}</code>`).join(" ")}</dd>`).join("")}</dl>
    ${s.proxmox ? `<p>PVE firewall: <b class="${s.proxmox.firewall_enabled ? "ok" : "warn"}">${s.proxmox.firewall_enabled ? "enabled" : "disabled"}</b></p>` : s.firewall ? `<p>Firewall: <b class="${s.firewall.active ? "ok" : "warn"}">${esc(s.firewall.kind)} ${s.firewall.active ? "active" : "inactive"}</b></p>` : `<p class="muted">No firewall detected</p>`}
    ${s.firewall?.rules.length ? `<pre>${esc(s.firewall.rules.join("\n"))}</pre>` : ""}`));

  if (s.proxmox) {
    const p = s.proxmox;
    sections.push(card(`Proxmox guests <span class="muted">PVE ${esc(p.version)}</span>`, tbl(["ID", "Name", "Status", "CPU", "RAM", "Disk", "IP"],
      p.guests.map((g) => {
        const linked = hostForGuest(g.name, g.ip);
        return [String(g.vmid), linked ? `<a data-view="${esc(linked.id)}">${esc(g.name)}</a>` : esc(g.name),
          `<span class="pill ${g.status === "running" ? "ok" : "warn"}">${esc(g.status)}</span> <span class="muted small">${g.type}${g.onboot ? " · onboot" : ""}</span>`,
          String(g.cores ?? "–"), bytes(g.memory), bytes(g.disk), g.ip ? `<code>${esc(g.ip)}</code>` : "–"];
      })), "wide"));
    sections.push(card("Storage", `
      <dl>${p.storage.map((x) => `<dt>${esc(x.name)}</dt><dd>${bytes(x.used)} / ${bytes(x.total)} <span class="muted">${esc(x.type)} · ${esc(x.content)}</span>${bar(x.used, x.total)}</dd>`).join("")}</dl>
      <p>Backup jobs: <b class="${p.backup_jobs ? "ok" : "crit"}">${p.backup_jobs}</b> · ${p.backups.length} backup files</p>
      ${p.backups.length ? tbl(["VMID", "Volume", "Size", "Date"], p.backups.map((b) => [String(b.vmid), `<code>${esc(b.volid.split("/").pop())}</code>`, bytes(b.size), date(b.ctime)])) : ""}`));
  }

  if (s.docker) {
    const d = s.docker;
    sections.push(card(`Docker <span class="muted">${esc(d.version ?? "")}</span>`, `
      ${tbl(["Name", "Image", "Status", "Ports"], d.containers.map((c) => [esc(c.name), `<code>${esc(c.image)}</code>`,
        `<span class="pill ${c.state === "running" && !/unhealthy/.test(c.status) ? "ok" : "warn"}">${esc(c.status)}</span>`, esc(c.ports || "–")]))}
      ${d.compose.length ? `<p class="small">${d.compose.map((p) => `compose <b>${esc(p.name)}</b> <span class="muted">${esc(p.status)}</span> <code>${esc(p.config)}</code>`).join("<br>")}</p>` : ""}
      ${d.volumes.length ? `<p class="small muted">Volumes: ${d.volumes.map(esc).join(", ")}</p>` : ""}`, "wide"));
  }

  if (s.tailscale) {
    const t = s.tailscale;
    sections.push(card("Tailscale", t.running ? `
      <dl>
        <dt>Address</dt><dd><code>${esc(t.ip)}</code> ${esc(t.dns)}</dd>
        <dt>Version</dt><dd>${esc(t.version)}</dd>
        ${t.routes?.length ? `<dt>Routes</dt><dd>${t.routes.map((r) => `<code>${esc(r)}</code>`).join(" ")}</dd>` : ""}
        ${(t.serve ?? []).map((x) => `<dt>Serve</dt><dd><code>${esc(x.url)}</code> → ${esc(x.target)}</dd>`).join("")}
      </dl>
      <p class="small muted">Peers: ${(t.peers ?? []).map((p) => `<span class="${p.online ? "" : "off"}">${esc(p.name)}</span>`).join(", ")}</p>` : `<p class="warn">Not running</p>`));
  }

  sections.push(card("Listening ports", tbl(["Proto", "Address", "Port", "Process"],
    (s.listeners ?? []).filter((l) => !(l.proto === "udp" && l.port > 32767)).map((l) => [l.proto, `<code class="${isWildcard(l) ? "warn" : ""}">${esc(l.addr)}</code>`, String(l.port), esc(l.process)]), "compact")));

  const us = Object.entries(s.user_services ?? {});
  sections.push(card("Services", `
    ${us.map(([u, l]) => `<p class="small"><b>${esc(u)}</b> (user): ${l.map((x) => `<span class="chip hl">${esc(x)}</span>`).join("")}</p>`).join("")}
    <div class="chips">${(s.services ?? []).map((x) => `<span class="chip">${esc(x)}</span>`).join("")}</div>`));

  sections.push(card("Notes", notesBox(id), "wide"));
  sections.push(`<details class="card wide"><summary>Raw snapshot</summary><pre>${esc(JSON.stringify(s, null, 2))}</pre></details>`);

  return head + `<div class="grid2">${sections.join("")}</div>`;
}

function addView() {
  const { snapshot: s, host: h } = draft;
  const step1 = card("Scan a new machine", `
    <p class="small muted">Enter an IP, hostname or ~/.ssh/config alias. Linux/macOS: key-based ssh and root or passwordless sudo. Windows: OpenSSH server and an admin account. New host keys are trusted on first use.</p>
    <div class="row">
      <label class="field">Address<input data-draft="addr" value="${esc(draft.addr)}" placeholder="192.168.1.20" autofocus></label>
      <label class="field">SSH user <input data-draft="user" value="${esc(draft.user)}" placeholder="default"></label>
    </div>
    <div class="actions"><button class="primary" data-action="probe" ${draft.probing || !draft.addr.trim() ? "disabled" : ""}>${draft.probing ? "Scanning…" : "Scan"}</button></div>`);
  if (!s || !h) return `<div class="grid2">${step1}</div>`;

  const ips = (s.addresses ?? []).filter((a) => a.iface !== "lo").flatMap((a) => a.addrs.filter((x) => !x.startsWith("fe80")));
  const dup = config.hosts.find((x) => x.ssh === h.ssh || x.name === h.name);
  const detected = card("Detected", `
    <dl>
      <dt>Hostname</dt><dd>${esc(s.hostname)}</dd>
      <dt>OS</dt><dd>${esc(s.os)} · ${esc(s.kernel)}</dd>
      <dt>CPU</dt><dd>${s.cpu.count}× ${esc(s.cpu.model)}</dd>
      <dt>Memory</dt><dd>${bytes(s.memory.total)}</dd>
      <dt>Addresses</dt><dd>${ips.map((x) => `<code>${esc(x)}</code>`).join(" ") || "–"}</dd>
      ${s.proxmox ? `<dt>Proxmox</dt><dd>PVE ${esc(s.proxmox.version)} · ${s.proxmox.guests.length} guests</dd>` : ""}
      ${s.docker ? `<dt>Docker</dt><dd>${s.docker.containers.length} containers</dd>` : ""}
      ${s.tailscale?.running ? `<dt>Tailscale</dt><dd><code>${esc(s.tailscale.ip)}</code> ${esc(s.tailscale.dns)}</dd>` : ""}
    </dl>`);
  const form = card("Host entry", `
    ${dup ? `<div class="banner warn">Looks like existing host <b>${esc(dup.name)}</b> (<code>${esc(dup.ssh)}</code>)</div>` : ""}
    <div class="row">
      <label class="field">Name<input data-host="name" value="${esc(h.name)}"></label>
      <label class="field">ID<input data-host="id" value="${esc(h.id)}"></label>
    </div>
    <label class="field">SSH target<input data-host="ssh" value="${esc(h.ssh)}"></label>
    <label class="field">Parent
      <select data-host="parent"><option value="">None</option>${config.hosts.map((x) => `<option value="${esc(x.id)}" ${x.id === h.parent ? "selected" : ""}>${esc(x.name)}</option>`).join("")}</select>
    </label>
    <label class="field">Role<input data-host="role" value="${esc(h.role ?? "")}"></label>
    <label class="field">Monitor ${monitorSelect(`data-host="monitor_min"`, h.monitor_min)}</label>
    <div class="actions right"><button data-action="add-cancel">Cancel</button><button class="primary" data-action="add-host">Add host</button></div>`);
  return `<div class="grid2">${step1}${form}${detected}</div>`;
}

async function probe() {
  const addr = draft.addr.trim(), user = draft.user.trim();
  if (!addr || draft.probing) return;
  const ssh = user ? `${user}@${addr}` : addr;
  draft = { addr, user, probing: true };
  render();
  try {
    const snapshot = await api.probeHost(ssh);
    draft = { ...draft, snapshot, host: inferHost(snapshot, ssh, addr) };
  } catch (e) {
    toast(`${ssh}: ${e}`, true);
  } finally {
    draft.probing = false;
    render();
  }
}

async function addHost() {
  const { host: h, snapshot } = draft;
  if (!h || !snapshot) return;
  const host: Host = { id: h.id.trim(), name: h.name.trim(), ssh: h.ssh.trim(), parent: h.parent || null, role: h.role?.trim() || null };
  if (h.monitor_min != null) host.monitor_min = Number(h.monitor_min);
  if (!host.id || !host.name || !host.ssh) return toast("ID, name and SSH target are required", true);
  try {
    await api.addHost(host, snapshot);
    [config, state] = await Promise.all([api.getConfig(), api.loadState()]);
    draft = { addr: "", user: "", probing: false };
    view = host.id;
    toast(`Added ${host.name}`);
    render();
  } catch (e) { toast(String(e), true); }
}

const notesBox = (id: string) =>
  `<textarea class="notes" data-notes="${esc(id)}" placeholder="Purpose, credentials location, todo…">${esc(notes[id] ?? "")}</textarea>`;

function settings() {
  return `
    <div class="grid2">
      ${card("General", `
        <label class="field">Docs folder (markdown export)<input id="docs_dir" value="${esc(config.docs_dir ?? "")}"></label>
        <label class="field">Default monitor interval <span class="muted small">(hosts can override)</span>
          <select id="interval">${[0, ...MONITOR_OPTIONS, 180, 720, 1440].map((m) => `<option value="${m}" ${config.scan_interval_min === m ? "selected" : ""}>${m === 0 ? "Manual only" : minLabel(m)}</option>`).join("")}</select>
        </label>
        <label class="field">Snapshots kept per host<input id="keep" type="number" min="2" value="${config.keep_snapshots}"></label>`)}
      ${card("Data", `
        <p class="small muted">Scans run <code>ssh &lt;target&gt;</code> using your ~/.ssh/config and pipe a shell (Linux/macOS, as root or via passwordless <code>sudo -n</code>) or PowerShell (Windows) collector script. Nothing is installed on hosts.</p>
        <button data-action="reveal">Show data folder</button>`)}
      ${card("Updates", `
        <p class="small muted">Version ${esc(version)}. Checks GitHub releases on launch and every 6 h.</p>
        ${update ? `<button class="primary" data-action="install-update" ${progress ? "disabled" : ""}>${progress ?? `Install ${esc(update.version)} &amp; restart`}</button>` : `<button data-action="check-update">Check for updates</button>`}`)}
      ${card("Hosts", `
        <p class="small muted">JSON array. Fields: <code>id</code>, <code>name</code>, <code>ssh</code> (alias or user@host), optional <code>parent</code> (host id), <code>role</code>, <code>monitor_min</code> (0 = off).</p>
        <textarea id="hosts" class="code" spellcheck="false">${esc(JSON.stringify(config.hosts, null, 2))}</textarea>`, "wide")}
    </div>
    <div class="actions right"><button class="primary" data-action="save-settings">Save settings</button></div>`;
}

// ---------- actions ----------

/** Monitored scans fail quietly; the host shows the error banner. */
async function scan(id: string, quiet = false) {
  if (scanning.has(id)) return;
  scanning.add(id);
  lastScan[id] = Date.now() / 1000;
  quiet ? softRender() : render();
  try {
    await api.scanHost(id);
  } catch (e) {
    if (!quiet) toast(`${config.hosts.find((h) => h.id === id)?.name}: ${e}`, true);
  } finally {
    scanning.delete(id);
    state = await api.loadState();
    quiet ? softRender() : render();
  }
}

const scanAll = () => Promise.allSettled(config.hosts.map((h) => scan(h.id)));

/** Scan every monitored host whose interval has elapsed. Before the first local attempt, uses the last stored scan/error. */
function monitorTick() {
  const now = Date.now() / 1000;
  for (const h of config.hosts) {
    const m = monitorMin(h);
    if (!m) continue;
    const st = state[h.id];
    const last = lastScan[h.id] ?? Math.min(now, Math.max(st?.latest?.collected_at ?? 0, st?.error?.at ?? 0));
    if (now - last >= m * 60) scan(h.id, true);
  }
}

async function setMonitor(id: string, value: string) {
  const hosts = config.hosts.map((h) => {
    if (h.id !== id) return h;
    const { monitor_min: _, ...rest } = h;
    return value === "" ? rest : { ...rest, monitor_min: Number(value) };
  });
  try {
    await api.saveConfig({ ...config, hosts });
    config = { ...config, hosts };
    monitorTick();
    render();
  } catch (e) { toast(String(e), true); }
}

async function checkUpdate(manual = false) {
  try {
    update = await check();
    if (manual && !update) toast("Up to date");
    render();
  } catch (e) {
    if (manual) toast(`Update check failed: ${e}`, true);
  }
}

async function installUpdate() {
  if (!update || progress) return;
  let total = 0, done = 0;
  progress = "Downloading…";
  render();
  try {
    await update.downloadAndInstall((ev) => {
      if (ev.event === "Started") total = ev.data.contentLength ?? 0;
      else if (ev.event === "Progress") { done += ev.data.chunkLength; if (total) { progress = `Downloading ${pct(done, total)}%`; render(); } }
      else progress = "Restarting…";
    });
    await relaunch();
  } catch (e) {
    progress = undefined;
    toast(`Update failed: ${e}`, true);
    render();
  }
}

let notesTimer: number | undefined;

document.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.target as HTMLElement).dataset?.draft) probe();
});

document.addEventListener("click", async (e) => {
  const el = (e.target as HTMLElement).closest<HTMLElement>("[data-view],[data-action]");
  if (!el || el.tagName === "SELECT") return;
  if (el.dataset.view) {
    view = el.dataset.view;
    render();
    document.querySelector(".content")?.scrollTo(0, 0);
    return;
  }
  switch (el.dataset.action) {
    case "scan": return scan(el.dataset.id!);
    case "scan-all": return scanAll();
    case "probe": return probe();
    case "add-host": return addHost();
    case "add-cancel": draft = { addr: "", user: "", probing: false }; render(); return;
    case "check-update": return checkUpdate(true);
    case "install-update": return installUpdate();
    case "reveal": return api.reveal().catch((err) => toast(String(err), true));
    case "export":
      try {
        const path = await api.exportMarkdown(toMarkdown(config, state, notes));
        toast(`Wrote ${path}`);
        api.reveal(path);
      } catch (err) { toast(String(err), true); }
      return;
    case "save-settings":
      try {
        const hosts = JSON.parse((document.querySelector("#hosts") as HTMLTextAreaElement).value) as Host[];
        if (!Array.isArray(hosts) || hosts.some((h) => !h.id || !h.name || !h.ssh)) throw new Error("each host needs id, name and ssh");
        if (new Set(hosts.map((h) => h.id)).size !== hosts.length) throw new Error("host ids must be unique");
        const next: Config = {
          hosts,
          docs_dir: (document.querySelector("#docs_dir") as HTMLInputElement).value.trim() || null,
          scan_interval_min: Number((document.querySelector("#interval") as HTMLSelectElement).value),
          keep_snapshots: Math.max(2, Number((document.querySelector("#keep") as HTMLInputElement).value) || 100),
        };
        await api.saveConfig(next);
        config = next;
        state = await api.loadState();
        monitorTick();
        toast("Settings saved");
        render();
      } catch (err) { toast(`Invalid settings: ${err instanceof Error ? err.message : err}`, true); }
      return;
  }
});

document.addEventListener("change", async (e) => {
  const el = e.target as HTMLSelectElement;
  if (el.dataset.host && draft.host) {
    (draft.host as any)[el.dataset.host] = el.value || null;
    return;
  }
  if (el.dataset.action === "monitor") return setMonitor(el.dataset.id!, el.value);
  if (el.dataset.action !== "compare") return;
  const id = el.dataset.id!;
  const ts = el.value ? Number(el.value) : undefined;
  if (ts && !compareCache[`${id}:${ts}`]) compareCache[`${id}:${ts}`] = await api.loadSnapshot(id, ts);
  compareWith[id] = ts;
  render();
});

document.addEventListener("input", (e) => {
  const el = e.target as HTMLTextAreaElement;
  if (el.dataset.draft === "addr" || el.dataset.draft === "user") {
    draft[el.dataset.draft] = el.value;
    document.querySelector<HTMLButtonElement>('[data-action="probe"]')!.disabled = draft.probing || !draft.addr.trim();
    return;
  }
  if (el.dataset.host && draft.host) {
    (draft.host as any)[el.dataset.host] = el.value;
    return;
  }
  if (!el.dataset.notes) return;
  notes[el.dataset.notes] = el.value;
  clearTimeout(notesTimer);
  notesTimer = window.setTimeout(() => api.saveNotes(notes).catch((err) => toast(String(err), true)), 600);
});

/** Re-render unless the user is editing a field (background scans, timestamp refresh). */
function softRender() {
  const a = document.activeElement;
  if (!(a instanceof HTMLTextAreaElement || a instanceof HTMLInputElement || a instanceof HTMLSelectElement)) render();
}

// Refresh relative timestamps without clobbering focused inputs.
setInterval(softRender, 60_000);

(async () => {
  try {
    [config, state, notes] = await Promise.all([api.getConfig(), api.loadState(), api.getNotes()]);
    render();
    monitorTick();
    setInterval(monitorTick, 30_000);
    version = await getVersion().catch(() => "");
    checkUpdate();
    setInterval(checkUpdate, 6 * 3600_000);
  } catch (e) {
    $app.innerHTML = `<div class="banner crit">Failed to start: ${esc(e)}</div>`;
  }
})();
