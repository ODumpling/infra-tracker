#!/bin/sh
# Remote inventory collector for Linux (POSIX sh, no Python). Piped over ssh to `sh -s` (run as root).
# Prints raw command output in `@@infra@@ <section>` blocks; parsed into a snapshot by src/collect.rs.
# Manual run: ssh host 'sudo sh -s' < src-tauri/collectors/linux.sh
export LC_ALL=C PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
command -v timeout >/dev/null 2>&1 || timeout() { shift; "$@"; }

has() { command -v "$1" >/dev/null 2>&1; }
sec() { printf '\n@@infra@@ %s\n' "$*"; }
# outt SECS NAME CMD...: section NAME with CMD's stdout, only if CMD succeeds
outt() { _t=$1 _n=$2; shift 2; _o=$(timeout "$_t" "$@" 2>/dev/null) && { sec "$_n"; printf '%s\n' "$_o"; }; }
out() { outt 20 "$@"; }

base() {
  sec platform; echo linux
  sec now; date +%s
  sec hostname; uname -n
  sec os_release; cat /etc/os-release
  sec kernel; uname -r
  sec uptime; cat /proc/uptime
  sec loadavg; cat /proc/loadavg
  sec nproc; getconf _NPROCESSORS_ONLN
  sec cpu_model; grep -m1 '^model name' /proc/cpuinfo | cut -d: -f2-
  sec meminfo; cat /proc/meminfo
}

disks() { out disks df -B1 -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs -x fuse --output=target,fstype,size,used; }
addresses() { out ip_addr ip -j addr; }
listeners() { out ss ss -tulnpH; }
services() { has systemctl && out services systemctl list-units --type=service --state=running --no-legend --plain; }

user_services() {
  for d in /run/user/*; do
    uid=${d##*/}
    case $uid in '' | *[!0-9]*) continue ;; esac
    [ "$uid" -ge 1000 ] || continue
    name=$(awk -F: -v u="$uid" '$3 == u { print $1; exit }' /etc/passwd)
    [ -n "$name" ] || continue
    out "user_services $name" runuser -u "$name" -- env XDG_RUNTIME_DIR="$d" systemctl --user list-units --type=service --state=running --no-legend --plain
  done
}

docker_() {
  has docker || return
  sec docker
  out docker_version docker version --format '{{.Server.Version}}'
  out docker_ps docker ps -a --format '{{json .}}'
  out docker_compose docker compose ls -a --format json
  out docker_volumes docker volume ls -q
}

tailscale_() {
  has tailscale || return
  sec tailscale
  out tailscale_status tailscale status --json
  out tailscale_serve tailscale serve status --json
  out tailscale_prefs tailscale debug prefs
}

firewall() {
  if has ufw; then
    sec ufw; timeout 20 ufw status
  elif has nft; then
    sec nft; timeout 20 nft list ruleset | grep -c 'hook input'
  fi
}

updates() {
  sec updates
  [ -e /var/run/reboot-required ] && echo reboot_required
  has apt-get && outt 60 apt_upgrades apt-get -s -o Debug::NoLocking=1 dist-upgrade
}

smart() {
  has smartctl || return
  sec smart
  lsblk -dno NAME,TYPE | while read -r name type; do
    [ "$type" = disk ] || continue
    sec "smart $name"; timeout 20 smartctl -j -H -A -i "/dev/$name"
  done
}

# Proxmox VE: lists via pvesh (in parallel), guest configs read straight from /etc/pve.
pv() { timeout 60 pvesh get "$@" --output-format json; }
proxmox() {
  has pvesh || return
  node=$(uname -n)
  sec proxmox
  sec pveversion; pveversion
  for k in qemu lxc storage; do (sec "pve_$k"; pv "/nodes/$node/$k") >"$T/pve_$k" 2>/dev/null & done
  (sec pve_firewall; pv /cluster/firewall/options) >"$T/pve_firewall" 2>/dev/null &
  (sec pve_backup_jobs; pv /cluster/backup) >"$T/pve_backup_jobs" 2>/dev/null &
  for kind in qemu lxc; do
    dir=/etc/pve/nodes/$node/$([ $kind = qemu ] && echo qemu-server || echo lxc)
    for f in "$dir"/*.conf; do
      [ -f "$f" ] || continue
      id=${f##*/}
      sec "pve_config $kind ${id%.conf}"; awk '/^\[/ { exit } 1' "$f"
    done
  done
  wait
  # backup listings for active storages holding backups (storage objects are flat, so split on '}')
  for s in $(tr '}' '\n' <"$T/pve_storage" | grep '"active":1' | grep '"content":"[^"]*backup' | grep -o '"storage":"[^"]*"' | cut -d'"' -f4); do
    (sec "pve_backups $s"; pv "/nodes/$node/storage/$s/content" --content backup) >"$T/pve_backups_$s" 2>/dev/null &
  done
  wait
}

main() {
  T=$(mktemp -d) || exit 1
  trap 'rm -rf "$T"' EXIT
  for f in base disks addresses listeners services user_services docker_ tailscale_ firewall updates smart proxmox; do
    "$f" >"$T/$f" 2>/dev/null &
  done
  wait
  cat "$T"/*
}

# stdin is the script itself; keep commands from reading it
main </dev/null
