# Infra Tracker

Small Tauri v2 desktop app (~3MB) that inventories homelab/VPS hosts over SSH and tracks changes over time.

## How it works
- Runs `ssh <target>` (uses `~/.ssh/config` + 1Password agent), detects the OS (`uname -s`; no `uname` → Windows) and pipes the matching script from `src-tauri/collectors/` to it: `linux.sh` / `macos.sh` to `sh` as root (direct or `sudo -n`), `windows.ps1` to `powershell`. No Python needed, nothing installed on hosts.
- Collects: OS/kernel/uptime, CPU/RAM/disks, SMART, addresses, listening ports, systemd services (+ user units), Docker containers/compose, Tailscale (IPs, routes, serve), firewall, pending updates/reboot, Proxmox guests/storage/backups/firewall.
- Each scan is saved as a JSON snapshot in SQLite (`~/Library/Application Support/dev.dufflebear.infratracker/infra.db`: tables `snapshots(host, ts, data)`, `scan_errors`, `notes`). Query with e.g. `sqlite3 infra.db "select host, ts, json_extract(data,'$.kernel') from snapshots"`. Host list/settings stay in `config.json`. Old `snapshots/` + `notes.json` are imported on first launch and renamed `*.imported`.
- UI computes **findings** (rules in `src/analyze.ts`) and **changes** vs previous/any older snapshot.
- Per-host notes; **Export markdown** writes `INVENTORY.md` to the docs folder (default `~/Code/Infrastructure`).
- Optional auto-scan interval (while app is open).

## Hosts
**+ Add host** (sidebar): enter IP/hostname/alias (+ optional ssh user) → app scans it → name, id, parent (matched against Proxmox guest IPs/names), role prefilled → edit → add. First scan saved as initial snapshot. New host keys trusted on first use (`StrictHostKeyChecking=accept-new`, probe only).

Or edit in Settings (JSON). Fields: `id`, `name`, `ssh` (alias or `user@host`), optional `parent` (host id, for VM nesting) and `role`.
Requirements per host: key-based ssh, plus root or passwordless sudo (Linux/macOS) or an admin account with OpenSSH server (Windows).

Coverage: Linux is full (systemd, apt, ufw/nftables, SMART via smartctl, Proxmox). macOS: launchd jobs, softwareupdate, Application Firewall, diskutil SMART. Windows: services, firewall profiles, Windows Update (last scan), disk health; load is approximated from CPU %. Docker and Tailscale everywhere.

## Dev
```sh
pnpm install
pnpm tauri dev          # app
pnpm dev                # then open http://localhost:1420/dev/mock.html — browser UI with mocked IPC (fixtures in dev/fixtures, git-ignored)
pnpm tauri build        # → src-tauri/target/release/bundle/{macos,dmg}
INFRA_TEST_HOST=pve cargo test --manifest-path src-tauri/Cargo.toml -- --ignored   # live ssh collector test
```

## Layout
- `src-tauri/collectors/{linux.sh,macos.sh,windows.ps1}` — remote collectors; print raw command output as `@@infra@@ <section>` blocks (run one by hand: `ssh host 'sudo sh -s' < src-tauri/collectors/linux.sh`)
- `src-tauri/src/collect.rs` — OS detection, ssh, parses sections into a snapshot
- `src-tauri/src/lib.rs` — commands: config, scan, snapshots (SQLite), notes, export
- `scripts/vm-scan.sh` — standalone ad-hoc text scan (`ssh user@host "sudo bash -s" < scripts/vm-scan.sh`)
- `src/analyze.ts` — findings + diff rules · `src/main.ts` — UI · `src/markdown.ts` — export

## License
MIT — see [LICENSE](LICENSE).
