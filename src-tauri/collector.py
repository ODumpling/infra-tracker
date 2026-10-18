#!/usr/bin/env python3
# Remote inventory collector. Piped over ssh to `python3 -` (run as root); prints one JSON object.
import json, os, platform, re, shutil, socket, subprocess, time
from concurrent.futures import ThreadPoolExecutor

POOL = ThreadPoolExecutor(max_workers=12)


def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.stdout if p.returncode == 0 else None
    except Exception:
        return None


def run_json(cmd, timeout=20):
    out = run(cmd, timeout)
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def has(binary):
    return shutil.which(binary) is not None


def os_release():
    info = {}
    try:
        for line in open("/etc/os-release"):
            k, _, v = line.strip().partition("=")
            info[k] = v.strip('"')
    except Exception:
        pass
    return info.get("PRETTY_NAME", platform.platform())


def meminfo():
    m = {}
    for line in open("/proc/meminfo"):
        k, v = line.split(":")
        m[k] = int(v.split()[0]) * 1024
    return {"total": m.get("MemTotal", 0), "available": m.get("MemAvailable", 0), "swap_total": m.get("SwapTotal", 0)}


def cpu():
    model = ""
    for line in open("/proc/cpuinfo"):
        if line.startswith("model name"):
            model = line.split(":", 1)[1].strip()
            break
    return {"model": model, "count": os.cpu_count()}


def disks():
    out = run("df -B1 -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs -x fuse --output=target,fstype,size,used") or ""
    res = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 4:
            res.append({"mount": parts[0], "fstype": parts[1], "size": int(parts[2]), "used": int(parts[3])})
    return res


def addresses():
    data = run_json("ip -j addr") or []
    res = []
    for iface in data:
        name = iface.get("ifname")
        if name == "lo" or name.startswith(("veth", "tap", "fwbr", "fwpr", "fwln")):
            continue
        addrs = [f'{a["local"]}/{a["prefixlen"]}' for a in iface.get("addr_info", []) if a.get("scope") == "global"]
        res.append({"iface": name, "state": iface.get("operstate"), "addrs": addrs})
    return res


PROC_RE = re.compile(r'\(\("([^"]+)"')


def listeners():
    out = run("ss -tulnpH") or ""
    res, seen = [], set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%")[0]
        m = PROC_RE.search(line)
        proc = m.group(1) if m else ""
        key = (proto, addr, port, proc)
        if key in seen:
            continue
        seen.add(key)
        res.append({"proto": proto, "addr": addr, "port": int(port) if port.isdigit() else 0, "process": proc})
    return sorted(res, key=lambda l: (l["port"], l["proto"], l["addr"]))


def services():
    out = run("systemctl list-units --type=service --state=running --no-legend --plain") or ""
    return sorted(l.split()[0].removesuffix(".service") for l in out.splitlines() if l.strip())


def user_services():
    res = {}
    try:
        users = os.listdir("/run/user")
    except Exception:
        return res
    for uid in users:
        if not uid.isdigit() or int(uid) < 1000:
            continue
        try:
            import pwd
            name = pwd.getpwuid(int(uid)).pw_name
        except Exception:
            continue
        out = run(f"runuser -u {name} -- env XDG_RUNTIME_DIR=/run/user/{uid} systemctl --user list-units --type=service --state=running --no-legend --plain")
        if out:
            svcs = [l.split()[0].removesuffix(".service") for l in out.splitlines() if l.strip()]
            noise = {"dbus", "pipewire", "pipewire-pulse", "wireplumber", "filter-chain", "xdg-document-portal", "xdg-permission-store"}
            svcs = sorted(s for s in svcs if s not in noise and not s.startswith(("gnome-", "org.gnome", "gvfs", "at-spi", "xdg-desktop")))
            if svcs:
                res[name] = svcs
    return res


def docker():
    if not has("docker"):
        return None
    version = (run("docker version --format '{{.Server.Version}}'") or "").strip() or None
    containers = []
    for line in (run("docker ps -a --format '{{json .}}'") or "").splitlines():
        try:
            c = json.loads(line)
        except Exception:
            continue
        containers.append({
            "name": c.get("Names"), "image": c.get("Image"), "state": c.get("State"),
            "status": c.get("Status"), "ports": c.get("Ports"),
            "project": (re.search(r"com\.docker\.compose\.project=([^,]+)", c.get("Labels", "")) or [None, None])[1],
        })
    compose = run_json("docker compose ls -a --format json") or []
    volumes = [l for l in (run("docker volume ls -q") or "").splitlines() if l]
    return {"version": version, "containers": containers,
            "compose": [{"name": p.get("Name"), "status": p.get("Status"), "config": p.get("ConfigFiles")} for p in compose],
            "volumes": volumes}


def tailscale():
    if not has("tailscale"):
        return None
    st = run_json("tailscale status --json")
    if not st:
        return {"running": False}
    me = st.get("Self", {})
    peers = [{"name": p.get("HostName"), "dns": p.get("DNSName", "").rstrip("."), "ips": p.get("TailscaleIPs", []),
              "os": p.get("OS"), "online": p.get("Online", False)} for p in (st.get("Peer") or {}).values()]
    serve = run_json("tailscale serve status --json") or {}
    serves = []
    for host, cfg in (serve.get("Web") or {}).items():
        for path, h in (cfg.get("Handlers") or {}).items():
            serves.append({"url": f"https://{host.replace(':443', '')}{path}" if host.endswith(":443") else f"http://{host}{path}",
                           "target": h.get("Proxy") or h.get("Path") or h.get("Text")})
    prefs = run_json("tailscale debug prefs") or {}
    return {"running": st.get("BackendState") == "Running", "ip": (me.get("TailscaleIPs") or [None])[0],
            "dns": me.get("DNSName", "").rstrip("."), "tailnet": (st.get("CurrentTailnet") or {}).get("Name"),
            "routes": prefs.get("AdvertiseRoutes") or [], "peers": sorted(peers, key=lambda p: p["name"] or ""),
            "serve": serves, "version": st.get("Version", "").split("-")[0]}


def firewall():
    if has("ufw"):
        out = run("ufw status") or ""
        active = "Status: active" in out
        rules = [l for l in out.splitlines()[4:] if l.strip()] if active else []
        return {"kind": "ufw", "active": active, "rules": rules}
    if has("nft"):
        out = run("nft list ruleset") or ""
        return {"kind": "nftables", "active": "hook input" in out, "rules": []}
    return None


def updates():
    out = run("apt-get -s -o Debug::NoLocking=1 dist-upgrade", timeout=60) if has("apt-get") else None
    pending = None if out is None else sum(1 for l in out.splitlines() if l.startswith("Inst "))
    security = None if out is None else sum(1 for l in out.splitlines() if l.startswith("Inst ") and "-security" in l)
    return {"pending": pending, "security": security, "reboot_required": os.path.exists("/var/run/reboot-required")}


def smart():
    if not has("smartctl"):
        return []
    res = []
    for line in (run("lsblk -dno NAME,TYPE,MODEL,SIZE -b") or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1] != "disk":
            continue
        name = parts[0]
        d = run_json(f"smartctl -j -H -A -i /dev/{name}") or {}
        res.append({"device": name, "model": d.get("model_name"), "passed": (d.get("smart_status") or {}).get("passed"),
                    "power_on_hours": (d.get("power_on_time") or {}).get("hours"),
                    "temp": (d.get("temperature") or {}).get("current")})
    return res


def proxmox():
    if not has("pvesh"):
        return None
    node = socket.gethostname()
    pv = lambda p: run_json(f"pvesh get {p} --output-format json", timeout=60)
    jobs = {k: POOL.submit(pv, path) for k, path in {
        "qemu": f"/nodes/{node}/qemu", "lxc": f"/nodes/{node}/lxc", "storage": f"/nodes/{node}/storage",
        "fw": "/cluster/firewall/options", "jobs": "/cluster/backup"}.items()}
    version = POOL.submit(run, "pveversion")
    qemu, lxc = jobs["qemu"].result() or [], jobs["lxc"].result() or []
    cfgs = {("qemu", g["vmid"]): POOL.submit(pv, f"/nodes/{node}/qemu/{g['vmid']}/config") for g in qemu}
    cfgs.update({("lxc", g["vmid"]): POOL.submit(pv, f"/nodes/{node}/lxc/{g['vmid']}/config") for g in lxc})
    storage = [{"name": s.get("storage"), "type": s.get("type"), "total": s.get("total"), "used": s.get("used"),
                "content": s.get("content"), "active": bool(s.get("active"))} for s in jobs["storage"].result() or []]
    backup_lists = [POOL.submit(pv, f"/nodes/{node}/storage/{s['name']}/content --content backup")
                    for s in storage if s["active"] and "backup" in (s["content"] or "")]
    guests = []
    for kind, items, netkey in (("qemu", qemu, "ipconfig0"), ("lxc", lxc, "net0")):
        for g in items:
            cfg = cfgs[(kind, g["vmid"])].result() or {}
            guests.append({"vmid": int(g["vmid"]), "name": g.get("name"), "status": g.get("status"), "type": kind,
                           "cores": cfg.get("cores"), "memory": g.get("maxmem"), "disk": g.get("maxdisk"),
                           "onboot": bool(cfg.get("onboot")), "uptime": g.get("uptime"),
                           "ip": (re.search(r"ip=([\d.]+)", cfg.get(netkey, "")) or [None, None])[1]})
    backups = [{"volid": b.get("volid"), "vmid": b.get("vmid"), "size": b.get("size"), "ctime": b.get("ctime")}
               for f in backup_lists for b in f.result() or []]
    ver = (version.result() or "").strip()
    return {"version": (re.search(r"pve-manager/([\d.]+)", ver) or [None, ver])[1], "node": node,
            "guests": sorted(guests, key=lambda g: g["vmid"]), "storage": storage,
            "backup_jobs": len(jobs["jobs"].result() or []), "backups": backups,
            "firewall_enabled": bool((jobs["fw"].result() or {}).get("enable"))}


def uptime():
    return float(open("/proc/uptime").read().split()[0])


SECTIONS = {
    "disks": disks, "addresses": addresses, "listeners": listeners, "services": services,
    "user_services": user_services, "docker": docker, "tailscale": tailscale, "firewall": firewall,
    "updates": updates, "smart": smart, "proxmox": proxmox,
}
futures = {k: POOL.submit(f) for k, f in SECTIONS.items()}
result = {
    "collected_at": int(time.time()),
    "hostname": socket.gethostname(),
    "os": os_release(),
    "kernel": platform.release(),
    "uptime": uptime(),
    "load": list(os.getloadavg()),
    "cpu": cpu(),
    "memory": meminfo(),
}
for k, f in futures.items():
    try:
        result[k] = f.result()
    except Exception as e:
        result[k] = None
        result.setdefault("errors", {})[k] = str(e)
print(json.dumps(result))
