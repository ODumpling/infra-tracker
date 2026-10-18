export interface Host {
  id: string;
  name: string;
  ssh: string;
  parent?: string | null;
  role?: string | null;
}

export interface Config {
  hosts: Host[];
  docs_dir?: string | null;
  scan_interval_min: number;
  keep_snapshots: number;
}

export interface Listener { proto: string; addr: string; port: number; process: string }
export interface Container { name: string; image: string; state: string; status: string; ports: string; project?: string | null }
export interface Guest {
  vmid: number; name: string; status: string; type: "qemu" | "lxc";
  cores?: number; memory?: number; disk?: number; onboot: boolean; ip?: string | null; uptime?: number;
}

export interface Snapshot {
  collected_at: number;
  hostname: string;
  os: string;
  kernel: string;
  uptime: number;
  load: number[];
  cpu: { model: string; count: number };
  memory: { total: number; available: number; swap_total: number };
  disks: { mount: string; fstype: string; size: number; used: number }[] | null;
  addresses: { iface: string; state: string; addrs: string[] }[] | null;
  listeners: Listener[] | null;
  services: string[] | null;
  user_services: Record<string, string[]> | null;
  docker: { version: string | null; containers: Container[]; compose: { name: string; status: string; config: string }[]; volumes: string[] } | null;
  tailscale: {
    running: boolean; ip?: string; dns?: string; tailnet?: string; routes?: string[]; version?: string;
    peers?: { name: string; dns: string; ips: string[]; os: string; online: boolean }[];
    serve?: { url: string; target: string }[];
  } | null;
  firewall: { kind: string; active: boolean; rules: string[] } | null;
  updates: { pending: number | null; security: number | null; reboot_required: boolean } | null;
  smart: { device: string; model: string | null; passed: boolean | null; power_on_hours: number | null; temp: number | null }[] | null;
  proxmox: {
    version: string; node: string; guests: Guest[];
    storage: { name: string; type: string; total: number; used: number; content: string; active: boolean }[];
    backup_jobs: number; backups: { volid: string; vmid: number; size: number; ctime: number }[];
    firewall_enabled: boolean;
  } | null;
  errors?: Record<string, string>;
}

export interface HostState {
  latest: Snapshot | null;
  previous: Snapshot | null;
  error: { at: number; message: string } | null;
  history: number[];
}

export type Severity = "crit" | "warn" | "info";
export interface Finding { severity: Severity; text: string }
export interface Change { kind: "added" | "removed" | "changed"; area: string; text: string }
