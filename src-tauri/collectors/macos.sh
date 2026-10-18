#!/bin/sh
# Remote inventory collector for macOS (POSIX sh, no Python). Piped over ssh to `sh -s` (run as root).
# Prints raw command output in `@@infra@@ <section>` blocks; parsed into a snapshot by src/collect.rs.
# Manual run: ssh host 'sudo sh -s' < src-tauri/collectors/macos.sh
export LC_ALL=C PATH="$PATH:/usr/local/bin:/opt/homebrew/bin:/usr/sbin:/usr/bin:/sbin:/bin:/Applications/Tailscale.app/Contents/MacOS"
has() { command -v "$1" >/dev/null 2>&1; }
has timeout || timeout() { perl -e 'alarm shift; exec @ARGV' "$@"; }
has tailscale || ! has Tailscale || tailscale() { Tailscale "$@"; }

sec() { printf '\n@@infra@@ %s\n' "$*"; }
# outt SECS NAME CMD...: section NAME with CMD's stdout, only if CMD succeeds
outt() { _t=$1 _n=$2; shift 2; _o=$(timeout "$_t" "$@" 2>/dev/null) && { sec "$_n"; printf '%s\n' "$_o"; }; }
out() { outt 20 "$@"; }

base() {
  sec platform; echo macos
  sec now; date +%s
  sec hostname; uname -n
  sec sw_vers; sw_vers
  sec kernel; uname -r
  sec sysctl; sysctl kern.boottime hw.ncpu hw.memsize machdep.cpu.brand_string vm.loadavg vm.swapusage
  sec vm_stat; vm_stat
}

disks() { sec df; df -kP; sec mount; mount; }
addresses() { out ifconfig ifconfig; }
listeners() { sec lsof; lsof +c 0 -nP -iTCP -sTCP:LISTEN; lsof +c 0 -nP -iUDP; }
services() { out launchctl launchctl list; }

user_services() {
  user=$(stat -f %Su /dev/console) uid=$(stat -f %u /dev/console)
  [ "$uid" -ge 500 ] 2>/dev/null || return
  out "launchctl_user $user" launchctl asuser "$uid" sudo -u "$user" launchctl list
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

firewall() { out alf /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --getstealthmode; }
updates() { outt 90 softwareupdate softwareupdate -l; }

smart() {
  sec smart
  for d in $(diskutil list physical | awk '/^\/dev\// { sub("/dev/", "", $1); print $1 }'); do
    if has smartctl; then
      sec "smart $d"; timeout 20 smartctl -j -H -A -i "/dev/$d"
    else
      out "diskutil $d" diskutil info "$d"
    fi
  done
}

main() {
  T=$(mktemp -d) || exit 1
  trap 'rm -rf "$T"' EXIT
  for f in base disks addresses listeners services user_services docker_ tailscale_ firewall updates smart; do
    "$f" >"$T/$f" 2>/dev/null &
  done
  wait
  cat "$T"/*
}

# stdin is the script itself; keep commands from reading it
main </dev/null
