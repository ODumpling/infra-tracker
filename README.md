# Infra Tracker

Small Tauri v2 desktop app (~3MB) that inventories homelab/VPS hosts over SSH and tracks changes over time.

## How it works
- Runs `ssh <target>` (uses `~/.ssh/config` + 1Password agent) and pipes `src-tauri/collector.py` to remote `python3` as root (direct or `sudo -n`). Nothing installed on hosts.
- Collects: OS/kernel/uptime, CPU/RAM/disks, SMART, addresses, listening ports, systemd services (+ user units), Docker containers/compose, Tailscale (IPs, routes, serve), firewall, pending updates/reboot, Proxmox guests/storage/backups/firewall.
- Each scan is saved as a JSON snapshot (`~/Library/Application Support/dev.otisdaley.infratracker/snapshots/<host>/<ts>.json`).
- UI computes **findings** (rules in `src/analyze.ts`) and **changes** vs previous/any older snapshot.
- Per-host notes; **Export markdown** writes `INVENTORY.md` to the docs folder (default `~/Code/Infrastructure`).
- Optional auto-scan interval (while app is open).

## Hosts
**+ Add host** (sidebar): enter IP/hostname/alias (+ optional ssh user) → app scans it → name, id, parent (matched against Proxmox guest IPs/names), role prefilled → edit → add. First scan saved as initial snapshot. New host keys trusted on first use (`StrictHostKeyChecking=accept-new`, probe only).

Or edit in Settings (JSON). Fields: `id`, `name`, `ssh` (alias or `user@host`), optional `parent` (host id, for VM nesting) and `role`.
Requirements per host: key-based ssh, `python3`, root or passwordless sudo.

## Dev
```sh
pnpm install
pnpm tauri dev          # app
pnpm dev                # then open http://localhost:1420/dev/mock.html — browser UI with mocked IPC (fixtures in dev/fixtures, git-ignored)
pnpm tauri build        # → src-tauri/target/release/bundle/{macos,dmg}
INFRA_TEST_HOST=pve cargo test --manifest-path src-tauri/Cargo.toml -- --ignored   # live ssh collector test
```

## Layout
- `src-tauri/collector.py` — remote collector (stdlib only, parallel sections)
- `src-tauri/src/lib.rs` — commands: config, scan, snapshots, notes, export
- `scripts/vm-scan.sh` — standalone ad-hoc text scan (`ssh user@host "sudo bash -s" < scripts/vm-scan.sh`)
- `src/analyze.ts` — findings + diff rules · `src/main.ts` — UI · `src/markdown.ts` — export
