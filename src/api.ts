import { invoke } from "@tauri-apps/api/core";
import type { Config, Host, HostState, Snapshot } from "./types";

export const api = {
  getConfig: () => invoke<Config>("get_config"),
  saveConfig: (config: Config) => invoke<void>("save_config", { config }),
  scanHost: (id: string) => invoke<Snapshot>("scan_host", { id }),
  probeHost: (ssh: string) => invoke<Snapshot>("probe_host", { ssh }),
  addHost: (host: Host, snapshot: Snapshot) => invoke<void>("add_host", { host, snapshot }),
  loadState: () => invoke<Record<string, HostState>>("load_state"),
  loadSnapshot: (id: string, ts: number) => invoke<Snapshot>("load_snapshot", { id, ts }),
  getNotes: () => invoke<Record<string, string>>("get_notes"),
  saveNotes: (notes: Record<string, string>) => invoke<void>("save_notes", { notes }),
  exportMarkdown: (content: string) => invoke<string>("export_markdown", { content }),
  reveal: (path?: string) => invoke<void>("reveal", { path }),
};
