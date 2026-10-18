// Browser harness: mocks Tauri IPC with fixture snapshots (dev/fixtures, git-ignored). Open /dev/mock.html under `pnpm dev`.
import { mockIPC } from "@tauri-apps/api/mocks";

const fixtures = import.meta.glob("./fixtures/*.json", { eager: true, import: "default" }) as Record<string, any>;
const fx = (n: string) => fixtures[`./fixtures/${n}.json`] ?? null;
const config = {
  hosts: [
    { id: "pve", name: "pve", ssh: "pve", role: "Proxmox host" },
    { id: "desktop", name: "desktop", ssh: "admin@192.168.1.60", parent: "pve", role: "VM 110 · dev desktop" },
    { id: "executor", name: "executor", ssh: "admin@192.168.1.61", parent: "pve", role: "VM 111 · Executor" },
    { id: "ovh-vps", name: "ovh-vps", ssh: "ovh-vps", role: "OVH VPS" },
    { id: "nas", name: "nas", ssh: "nas", role: "unreachable example" },
  ],
  docs_dir: "/tmp", scan_interval_min: 0, keep_snapshots: 100,
};
const state = () => Object.fromEntries(config.hosts.map((h) => {
  const latest = fx(h.id), previous = fx(`${h.id}-old`);
  return [h.id, { latest, previous, history: [latest, previous].filter(Boolean).map((s: any) => s.collected_at),
    error: h.id === "nas" ? { at: Date.now() / 1000 - 300, message: "ssh: Could not resolve hostname nas" } : null }];
}));
mockIPC(async (cmd, args: any) => {
  switch (cmd) {
    case "get_config": return config;
    case "load_state": return state();
    case "get_notes": return { pve: "Lenovo M910q in the closet." };
    case "scan_host": await new Promise((r) => setTimeout(r, 800)); if (args.id === "nas") throw "ssh: Could not resolve hostname nas"; return fx(args.id);
    case "probe_host": await new Promise((r) => setTimeout(r, 800)); if (args.ssh.includes("bad")) throw "ssh: connect to host bad port 22: Connection refused";
      return { ...fx("executor"), hostname: "newbox.lan", collected_at: Math.floor(Date.now() / 1000) };
    case "add_host": config.hosts.push(args.host); return null;
    case "load_snapshot": return [fx(args.id), fx(`${args.id}-old`)].find((s: any) => s?.collected_at === args.ts);
    case "export_markdown": console.log(args.content); (window as any).__md = args.content; return "/tmp/INVENTORY.md";
    default: return null;
  }
});
await import("../src/main");
