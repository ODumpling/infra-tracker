//! Remote inventory collection. Detects the host OS, pipes the matching script from `collectors/` over ssh and
//! parses its `@@infra@@ <section>` output into a snapshot (shape: `Snapshot` in src/types.ts).
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Output, Stdio};

const LINUX: &str = include_str!("../collectors/linux.sh");
const MACOS: &str = include_str!("../collectors/macos.sh");
const WINDOWS: &str = include_str!("../collectors/windows.ps1");

/// Prints the OS name, then runs the script from stdin as root (directly, or via passwordless sudo).
/// Also parses in cmd.exe/PowerShell, where `uname` is missing so it fails without output → Windows.
const UNIX_CMD: &str = r#"uname -s && sh -c 'if [ "$(id -u)" = 0 ]; then exec sh -s; else exec sudo -n sh -s; fi'"#;
/// Runs the script from stdin. Sent as -EncodedCommand so no quoting survives cmd.exe/PowerShell differences.
const WINDOWS_BOOTSTRAP: &str = "Invoke-Expression ([Console]::In.ReadToEnd())";

/// `accept_new`: trust-on-first-use for hosts not yet in known_hosts (only for explicit add-host probes).
pub fn collect(dest: &str, accept_new: bool) -> Result<Value, String> {
    let mut child = ssh(dest, accept_new, UNIX_CMD)?;
    let mut stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
    let mut os = String::new();
    stdout.read_line(&mut os).map_err(err)?;
    let script = match os.trim() {
        "Linux" => Some(LINUX),
        "Darwin" => Some(MACOS),
        _ => None,
    };
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    if let Some(s) = script {
        stdin.write_all(s.as_bytes()).map_err(err)?;
    }
    drop(stdin);
    let mut out = Vec::new();
    stdout.read_to_end(&mut out).map_err(err)?;
    let res = child.wait_with_output().map_err(err)?;
    if script.is_some() {
        return finish(Output { stdout: out, ..res });
    }
    // 255 = ssh itself failed (unreachable, auth, ...)
    if res.status.code() == Some(255) {
        return Err(ssh_error(&res));
    }
    let os = os.trim();
    if !os.is_empty() && !["MINGW", "MSYS", "CYGWIN"].iter().any(|p| os.starts_with(p)) {
        return Err(format!("unsupported OS: {os}"));
    }
    let cmd = format!("powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}", encode_command(WINDOWS_BOOTSTRAP));
    let mut child = ssh(dest, accept_new, &cmd)?;
    child.stdin.take().ok_or("no stdin")?.write_all(WINDOWS.as_bytes()).map_err(err)?;
    finish(child.wait_with_output().map_err(err)?)
}

fn ssh(dest: &str, accept_new: bool, cmd: &str) -> Result<Child, String> {
    Command::new("ssh")
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3"])
        .args(if accept_new { &["-o", "StrictHostKeyChecking=accept-new"][..] } else { &[] })
        .arg("--")
        .arg(dest)
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to run ssh: {e}"))
}

fn finish(out: Output) -> Result<Value, String> {
    if !out.status.success() {
        return Err(ssh_error(&out));
    }
    parse(&String::from_utf8_lossy(&out.stdout))
}

fn ssh_error(out: &Output) -> String {
    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if err.contains("agent") && (err.contains("communication with agent failed") || err.contains("agent refused")) {
        return format!("{err}\n(SSH agent refused — is 1Password unlocked?)");
    }
    if err.is_empty() { format!("ssh exited with {}", out.status) } else { err }
}

/// PowerShell -EncodedCommand: base64 of UTF-16LE.
fn encode_command(s: &str) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { B64[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Collector output split into `@@infra@@ <name>` sections.
struct Sections(HashMap<String, String>);

impl Sections {
    fn parse(out: &str) -> Self {
        let out = format!("\n{}", out.replace("\r\n", "\n"));
        let map = out
            .split("\n@@infra@@ ")
            .skip(1)
            .map(|chunk| {
                let (name, body) = chunk.split_once('\n').unwrap_or((chunk, ""));
                (name.trim().to_string(), body.trim().to_string())
            })
            .collect();
        Sections(map)
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    fn text(&self, name: &str) -> &str {
        self.get(name).unwrap_or_default()
    }

    /// Missing or empty → None.
    fn json(&self, name: &str) -> Result<Option<Value>, String> {
        match self.get(name).filter(|b| !b.is_empty()) {
            Some(b) => serde_json::from_str(b).map(Some).map_err(|e| format!("{name}: {e}")),
            None => Ok(None),
        }
    }

    fn json_list(&self, name: &str) -> Result<Vec<Value>, String> {
        Ok(match self.json(name)? {
            Some(Value::Array(a)) => a,
            _ => vec![],
        })
    }

    /// Sections named `<prefix> <arg>`, sorted by arg.
    fn args(&self, prefix: &str) -> Vec<(&str, &str)> {
        let mut v: Vec<_> = self
            .0
            .iter()
            .filter_map(|(k, b)| Some((k.strip_prefix(prefix)?.strip_prefix(' ')?, b.as_str())))
            .collect();
        v.sort();
        v
    }
}

type Fields = Vec<(&'static str, Result<Value, String>)>;

const KEYS: &[&str] = &[
    "collected_at", "hostname", "os", "kernel", "uptime", "load", "cpu", "memory", "disks", "addresses", "listeners", "services",
    "user_services", "docker", "tailscale", "firewall", "updates", "smart", "proxmox",
];

fn parse(out: &str) -> Result<Value, String> {
    let s = Sections::parse(out);
    let Some(platform) = s.get("platform") else {
        let head: String = out.trim().chars().take(300).collect();
        return Err(format!("bad collector output: {head}"));
    };
    let mut fields: Fields = vec![
        ("collected_at", Ok(json!(s.text("now").parse::<u64>().unwrap_or_else(|_| crate::now())))),
        ("hostname", Ok(json!(s.text("hostname")))),
        ("docker", docker(&s)),
        ("tailscale", tailscale(&s)),
    ];
    fields.extend(match platform {
        "linux" => linux(&s),
        "macos" => macos(&s),
        _ => vec![],
    });
    // already in snapshot shape (Windows)
    for (key, _) in s.args("json") {
        if let Some(k) = KEYS.iter().find(|k| **k == key) {
            fields.push((k, s.json(&format!("json {key}")).map(Option::unwrap_or_default)));
        }
    }

    let mut snap = Map::new();
    let mut errors = Map::new();
    snap.insert("platform".into(), json!(platform));
    for k in KEYS {
        snap.insert(k.to_string(), Value::Null);
    }
    for (k, v) in fields {
        match v {
            Ok(v) => snap.insert(k.into(), v),
            Err(e) => errors.insert(k.into(), e.into()),
        };
    }
    if let Some(Value::Array(l)) = snap.get_mut("listeners") {
        let key = |l: &Value| (l["port"].as_u64(), l["proto"].to_string(), l["addr"].to_string(), l["process"].to_string());
        l.sort_by_key(key);
        l.dedup_by_key(|l| key(l));
    }
    if !errors.is_empty() {
        snap.insert("errors".into(), Value::Object(errors));
    }
    Ok(Value::Object(snap))
}

// ---- helpers

/// `key<sep>value` lines.
fn kv(text: &str, sep: char) -> HashMap<&str, &str> {
    text.lines().filter_map(|l| l.split_once(sep)).map(|(k, v)| (k.trim(), v.trim())).collect()
}

fn floats(text: &str) -> Vec<f64> {
    text.split(|c: char| c.is_whitespace() || c == '{' || c == '}').filter_map(|t| t.parse().ok()).collect()
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Number or numeric string.
fn as_u64(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}

/// `ip=10.0.0.5/24,...` → `10.0.0.5`
fn ip_from_net(cfg: &str) -> Option<String> {
    let rest = &cfg[cfg.find("ip=")? + 3..];
    let ip: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    (!ip.is_empty()).then_some(ip)
}

fn sorted_unique(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

fn listener(proto: &str, local: &str, process: &str) -> Value {
    let (addr, port) = local.rsplit_once(':').unwrap_or(("", local));
    let addr = addr.trim_matches(['[', ']']).split('%').next().unwrap_or_default();
    json!({ "proto": proto, "addr": addr, "port": port.parse::<u64>().unwrap_or(0), "process": process })
}

fn smartctl(device: &str, body: &str) -> Value {
    let d: Value = serde_json::from_str(body).unwrap_or_default();
    json!({
        "device": device, "model": d["model_name"], "passed": d["smart_status"]["passed"],
        "power_on_hours": d["power_on_time"]["hours"], "temp": d["temperature"]["current"],
    })
}

// ---- shared (docker / tailscale run the same CLI everywhere)

fn docker(s: &Sections) -> Result<Value, String> {
    if !s.has("docker") {
        return Ok(Value::Null);
    }
    let containers: Vec<Value> = s
        .text("docker_ps")
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .map(|c| {
            let project = c["Labels"].as_str().unwrap_or_default().split(',').find_map(|l| l.strip_prefix("com.docker.compose.project="));
            json!({ "name": c["Names"], "image": c["Image"], "state": c["State"], "status": c["Status"], "ports": c["Ports"], "project": project })
        })
        .collect();
    let compose: Vec<Value> = s
        .json_list("docker_compose")?
        .iter()
        .map(|p| json!({ "name": p["Name"], "status": p["Status"], "config": p["ConfigFiles"] }))
        .collect();
    Ok(json!({
        "version": s.get("docker_version").filter(|v| !v.is_empty()),
        "containers": containers,
        "compose": compose,
        "volumes": s.text("docker_volumes").lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>(),
    }))
}

fn tailscale(s: &Sections) -> Result<Value, String> {
    if !s.has("tailscale") {
        return Ok(Value::Null);
    }
    let Some(st) = s.json("tailscale_status")? else { return Ok(json!({ "running": false })) };
    let dns = |v: &Value| v.as_str().unwrap_or_default().trim_end_matches('.').to_string();
    let me = &st["Self"];
    let mut peers: Vec<Value> = st["Peer"]
        .as_object()
        .into_iter()
        .flat_map(Map::values)
        .map(|p| {
            json!({ "name": p["HostName"], "dns": dns(&p["DNSName"]), "ips": p.get("TailscaleIPs").cloned().unwrap_or(json!([])),
                    "os": p["OS"], "online": p["Online"].as_bool().unwrap_or(false) })
        })
        .collect();
    peers.sort_by_key(|p| p["name"].as_str().unwrap_or_default().to_string());
    let serve = s.json("tailscale_serve")?.unwrap_or_default();
    let mut serves = vec![];
    for (host, cfg) in serve["Web"].as_object().into_iter().flatten() {
        for (path, h) in cfg["Handlers"].as_object().into_iter().flatten() {
            let url = match host.strip_suffix(":443") {
                Some(h) => format!("https://{h}{path}"),
                None => format!("http://{host}{path}"),
            };
            let target = ["Proxy", "Path", "Text"].iter().find_map(|k| h[k].as_str().filter(|t| !t.is_empty()));
            serves.push(json!({ "url": url, "target": target }));
        }
    }
    let prefs = s.json("tailscale_prefs")?.unwrap_or_default();
    Ok(json!({
        "running": st["BackendState"] == "Running",
        "ip": me["TailscaleIPs"][0],
        "dns": dns(&me["DNSName"]),
        "tailnet": st["CurrentTailnet"]["Name"],
        "routes": if prefs["AdvertiseRoutes"].is_array() { prefs["AdvertiseRoutes"].clone() } else { json!([]) },
        "peers": peers,
        "serve": serves,
        "version": st["Version"].as_str().unwrap_or_default().split('-').next(),
    }))
}

// ---- Linux

fn linux(s: &Sections) -> Fields {
    let kernel = s.text("kernel");
    let os = kv(s.text("os_release"), '=').get("PRETTY_NAME").map(|v| v.trim_matches('"').to_string());
    let mem: HashMap<&str, u64> = kv(s.text("meminfo"), ':')
        .into_iter()
        .filter_map(|(k, v)| Some((k, v.split_whitespace().next()?.parse::<u64>().ok()? * 1024)))
        .collect();
    let m = |k| mem.get(k).copied().unwrap_or(0);
    vec![
        ("os", Ok(json!(os.unwrap_or_else(|| format!("Linux {kernel}"))))),
        ("kernel", Ok(json!(kernel))),
        ("uptime", Ok(json!(floats(s.text("uptime")).first().copied().unwrap_or(0.0)))),
        ("load", Ok(json!(floats(s.text("loadavg")).into_iter().take(3).collect::<Vec<_>>()))),
        ("cpu", Ok(json!({ "model": s.text("cpu_model").trim(), "count": s.text("nproc").parse::<u64>().ok() }))),
        ("memory", Ok(json!({ "total": m("MemTotal"), "available": m("MemAvailable"), "swap_total": m("SwapTotal") }))),
        ("disks", Ok(linux_disks(s.text("disks")))),
        ("addresses", linux_addresses(s)),
        ("listeners", Ok(linux_listeners(s.text("ss")))),
        ("services", Ok(json!(systemd_units(s.text("services"))))),
        ("user_services", Ok(linux_user_services(s))),
        ("firewall", Ok(linux_firewall(s))),
        ("updates", Ok(linux_updates(s))),
        ("smart", Ok(json!(s.args("smart").into_iter().map(|(d, b)| smartctl(d, b)).collect::<Vec<_>>()))),
        ("proxmox", proxmox(s)),
    ]
}

fn linux_disks(df: &str) -> Value {
    df.lines()
        .skip(1)
        .filter_map(|l| match l.split_whitespace().collect::<Vec<_>>()[..] {
            [mount, fstype, size, used] => Some(json!({ "mount": mount, "fstype": fstype, "size": size.parse::<u64>().ok()?, "used": used.parse::<u64>().ok()? })),
            _ => None,
        })
        .collect()
}

fn linux_addresses(s: &Sections) -> Result<Value, String> {
    let skip = ["veth", "tap", "fwbr", "fwpr", "fwln"];
    Ok(s.json_list("ip_addr")?
        .iter()
        .filter_map(|iface| {
            let name = iface["ifname"].as_str()?;
            if name == "lo" || skip.iter().any(|p| name.starts_with(p)) {
                return None;
            }
            let addrs: Vec<String> = iface["addr_info"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|a| a["scope"] == "global")
                .map(|a| format!("{}/{}", a["local"].as_str().unwrap_or_default(), a["prefixlen"]))
                .collect();
            Some(json!({ "iface": name, "state": iface["operstate"], "addrs": addrs }))
        })
        .collect())
}

fn linux_listeners(ss: &str) -> Value {
    ss.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let (proto, local) = (parts.first()?, parts.get(4)?);
            // users:(("sshd",pid=1,fd=3))
            let process = line.split_once("((\"").and_then(|(_, r)| r.split_once('"')).map(|(p, _)| p).unwrap_or_default();
            Some(listener(proto, local, process))
        })
        .collect()
}

fn systemd_units(text: &str) -> Vec<String> {
    sorted_unique(
        text.lines()
            .filter_map(|l| l.split_whitespace().next())
            .map(|u| u.strip_suffix(".service").unwrap_or(u).to_string())
            .collect(),
    )
}

fn linux_user_services(s: &Sections) -> Value {
    let noise = ["dbus", "pipewire", "pipewire-pulse", "wireplumber", "filter-chain", "xdg-document-portal", "xdg-permission-store"];
    let noise_prefix = ["gnome-", "org.gnome", "gvfs", "at-spi", "xdg-desktop"];
    let mut res = Map::new();
    for (user, body) in s.args("user_services") {
        let svcs: Vec<String> = systemd_units(body)
            .into_iter()
            .filter(|u| !noise.contains(&u.as_str()) && !noise_prefix.iter().any(|p| u.starts_with(p)))
            .collect();
        if !svcs.is_empty() {
            res.insert(user.into(), json!(svcs));
        }
    }
    Value::Object(res)
}

fn linux_firewall(s: &Sections) -> Value {
    if let Some(out) = s.get("ufw") {
        let active = out.contains("Status: active");
        let rules: Vec<&str> = if active { out.lines().skip(4).filter(|l| !l.trim().is_empty()).collect() } else { vec![] };
        json!({ "kind": "ufw", "active": active, "rules": rules })
    } else if let Some(n) = s.get("nft") {
        json!({ "kind": "nftables", "active": n.trim().parse::<u64>().unwrap_or(0) > 0, "rules": [] })
    } else {
        Value::Null
    }
}

fn linux_updates(s: &Sections) -> Value {
    let inst = s.get("apt_upgrades").map(|o| o.lines().filter(|l| l.starts_with("Inst ")).collect::<Vec<_>>());
    json!({
        "pending": inst.as_ref().map(Vec::len),
        "security": inst.as_ref().map(|i| i.iter().filter(|l| l.contains("-security")).count()),
        "reboot_required": s.text("updates").contains("reboot_required"),
    })
}

fn proxmox(s: &Sections) -> Result<Value, String> {
    if !s.has("proxmox") {
        return Ok(Value::Null);
    }
    // `pve_config <kind> <vmid>` → raw /etc/pve config (`key: value` lines)
    let configs: HashMap<(&str, u64), HashMap<&str, &str>> = s
        .args("pve_config")
        .into_iter()
        .filter_map(|(arg, body)| {
            let (kind, id) = arg.split_once(' ')?;
            Some(((kind, id.parse().ok()?), kv(body, ':')))
        })
        .collect();
    let mut guests = vec![];
    for (kind, net) in [("qemu", "ipconfig0"), ("lxc", "net0")] {
        for g in s.json_list(&format!("pve_{kind}"))? {
            let Some(vmid) = as_u64(&g["vmid"]) else { continue };
            let cfg = configs.get(&(kind, vmid));
            let get = |k: &str| cfg.and_then(|c| c.get(k)).copied();
            guests.push(json!({
                "vmid": vmid, "name": g["name"], "status": g["status"], "type": kind,
                "cores": get("cores").and_then(|c| c.parse::<u64>().ok()), "memory": g["maxmem"], "disk": g["maxdisk"],
                "onboot": get("onboot").is_some_and(|v| v != "0"), "uptime": g["uptime"], "ip": get(net).and_then(ip_from_net),
            }));
        }
    }
    guests.sort_by_key(|g| g["vmid"].as_u64());
    let storage: Vec<Value> = s
        .json_list("pve_storage")?
        .iter()
        .map(|st| json!({ "name": st["storage"], "type": st["type"], "total": st["total"], "used": st["used"], "content": st["content"], "active": truthy(&st["active"]) }))
        .collect();
    let mut backups = vec![];
    for (name, _) in s.args("pve_backups") {
        for b in s.json_list(&format!("pve_backups {name}"))? {
            backups.push(json!({ "volid": b["volid"], "vmid": b["vmid"], "size": b["size"], "ctime": b["ctime"] }));
        }
    }
    let ver = s.text("pveversion");
    let version = ver
        .split_once("pve-manager/")
        .map(|(_, r)| r.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect::<String>())
        .unwrap_or_else(|| ver.to_string());
    Ok(json!({
        "version": version, "node": s.text("hostname"), "guests": guests, "storage": storage,
        "backup_jobs": s.json_list("pve_backup_jobs")?.len(), "backups": backups,
        "firewall_enabled": truthy(&s.json("pve_firewall")?.unwrap_or_default()["enable"]),
    }))
}

// ---- macOS

fn macos(s: &Sections) -> Fields {
    let v = kv(s.text("sw_vers"), ':');
    let os = format!("{} {} ({})", v.get("ProductName").unwrap_or(&"macOS"), v.get("ProductVersion").unwrap_or(&""), v.get("BuildVersion").unwrap_or(&""));
    let ctl: HashMap<&str, &str> = s.text("sysctl").lines().filter_map(|l| l.split_once(": ")).collect();
    let ctl_u64 = |k| ctl.get(k).and_then(|v| v.parse::<u64>().ok());
    // `{ sec = 1789123065, usec = 354577 } Fri Sep ...`
    let boot = ctl.get("kern.boottime").and_then(|b| b.split_once("sec = ")?.1.split(',').next()?.parse::<u64>().ok());
    let now = s.text("now").parse::<u64>().unwrap_or_else(|_| crate::now());
    let total = ctl_u64("hw.memsize").unwrap_or(0);
    vec![
        ("os", Ok(json!(os))),
        ("kernel", Ok(json!(s.text("kernel")))),
        ("uptime", Ok(json!(boot.map_or(0, |b| now.saturating_sub(b))))),
        ("load", Ok(json!(ctl.get("vm.loadavg").map(|l| floats(l)).unwrap_or_default()))),
        ("cpu", Ok(json!({ "model": ctl.get("machdep.cpu.brand_string"), "count": ctl_u64("hw.ncpu") }))),
        ("memory", Ok(json!({ "total": total, "available": mac_available(s.text("vm_stat"), total), "swap_total": ctl.get("vm.swapusage").map_or(0, |u| mac_swap(u)) }))),
        ("disks", Ok(mac_disks(s.text("df"), s.text("mount")))),
        ("addresses", Ok(mac_addresses(s.text("ifconfig")))),
        ("listeners", Ok(mac_listeners(s.text("lsof")))),
        ("services", Ok(json!(launchd_jobs(s.text("launchctl"))))),
        ("user_services", Ok(Value::Object(
            s.args("launchctl_user").into_iter().map(|(u, b)| (u.to_string(), json!(launchd_jobs(b)))).filter(|(_, l)| truthy(l)).collect(),
        ))),
        ("firewall", Ok(s.get("alf").map_or(Value::Null, |a| {
            let mut lines = a.lines();
            json!({ "kind": "macos", "active": lines.next().is_some_and(|l| l.contains("enabled")), "rules": lines.collect::<Vec<_>>() })
        }))),
        // softwareupdate can't tell security updates apart or whether a reboot is pending
        ("updates", Ok(json!({
            "pending": s.get("softwareupdate").map(|o| o.lines().filter(|l| l.trim_start().starts_with("* Label:")).count()),
            "security": null, "reboot_required": false,
        }))),
        ("smart", Ok(json!(s.args("smart").into_iter().map(|(d, b)| smartctl(d, b))
            .chain(s.args("diskutil").into_iter().map(|(d, b)| {
                let info = kv(b, ':');
                let passed = match info.get("SMART Status") { Some(&"Verified") => json!(true), Some(&"Failing") => json!(false), _ => Value::Null };
                json!({ "device": d, "model": info.get("Device / Media Name"), "passed": passed, "power_on_hours": null, "temp": null })
            }))
            .collect::<Vec<_>>()))),
    ]
}

/// Activity Monitor's "available": total − (app memory + wired + compressed).
fn mac_available(vm_stat: &str, total: u64) -> u64 {
    let page = vm_stat.split_once("page size of ").and_then(|(_, r)| r.split_whitespace().next()?.parse::<u64>().ok()).unwrap_or(4096);
    let pages: HashMap<&str, u64> = kv(vm_stat, ':').into_iter().filter_map(|(k, v)| Some((k, v.trim_end_matches('.').parse().ok()?))).collect();
    let p = |k| pages.get(k).copied().unwrap_or(0);
    if pages.contains_key("Anonymous pages") {
        let used = p("Anonymous pages").saturating_sub(p("Pages purgeable")) + p("Pages wired down") + p("Pages occupied by compressor");
        total.saturating_sub(used * page)
    } else {
        (p("Pages free") + p("Pages inactive") + p("Pages speculative")) * page
    }
}

/// `total = 7168.00M  used = ...`
fn mac_swap(usage: &str) -> u64 {
    let Some(t) = usage.split_once("total = ").and_then(|(_, r)| r.split_whitespace().next()) else { return 0 };
    let (num, unit) = t.split_at(t.len().saturating_sub(1));
    let mult = match unit {
        "K" => 1 << 10,
        "M" => 1 << 20,
        "G" => 1 << 30,
        _ => 1,
    };
    (num.parse::<f64>().unwrap_or(0.0) * mult as f64) as u64
}

fn mac_disks(df: &str, mount: &str) -> Value {
    // `/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse)`
    let mounts: HashMap<&str, Vec<&str>> = mount
        .lines()
        .filter_map(|l| {
            let (left, opts) = l.rsplit_once(" (")?;
            Some((left.split_once(" on ")?.1, opts.trim_end_matches(')').split(", ").collect()))
        })
        .collect();
    df.lines()
        .skip(1)
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            // `Filesystem 1024-blocks Used Available Capacity Mounted on`; filesystem and mount may contain spaces
            let i = (4..t.len()).find(|&i| t[i].ends_with('%') && t[i - 3..i].iter().all(|n| n.parse::<u64>().is_ok()))?;
            let mp = t[i + 1..].join(" ");
            let opts = mounts.get(mp.as_str())?;
            let fstype = *opts.first()?;
            if ["devfs", "autofs", "nullfs"].contains(&fstype) || (opts.contains(&"nobrowse") && mp != "/" && mp != "/System/Volumes/Data") {
                return None;
            }
            Some(json!({ "mount": mp, "fstype": fstype, "size": t[i - 3].parse::<u64>().ok()? * 1024, "used": t[i - 2].parse::<u64>().ok()? * 1024 }))
        })
        .collect()
}

/// Interfaces with at least one global address.
fn mac_addresses(ifconfig: &str) -> Value {
    let mut res: Vec<Value> = vec![];
    let mut cur: Option<(String, String, Vec<String>)> = None;
    let mut flush = |cur: &mut Option<(String, String, Vec<String>)>| {
        if let Some((name, state, addrs)) = cur.take().filter(|c| !c.2.is_empty() && c.0 != "lo0") {
            res.push(json!({ "iface": name, "state": state, "addrs": addrs }));
        }
    };
    for line in ifconfig.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if !line.starts_with(['\t', ' ']) {
            flush(&mut cur);
            let Some((name, rest)) = line.split_once(": ") else { continue };
            let up = rest.split_once('<').and_then(|(_, r)| r.split_once('>')).is_some_and(|(f, _)| f.split(',').any(|f| f == "UP"));
            cur = Some((name.to_string(), if up { "UP" } else { "DOWN" }.into(), vec![]));
        } else if let Some((_, state, addrs)) = cur.as_mut() {
            match t[..] {
                ["status:", s, ..] => *state = if s == "active" { "UP" } else { "DOWN" }.into(),
                ["inet", ip, ..] if !ip.starts_with("127.") && !ip.starts_with("169.254.") => {
                    let mask = t.iter().position(|w| *w == "netmask").and_then(|i| u32::from_str_radix(t.get(i + 1)?.trim_start_matches("0x"), 16).ok());
                    addrs.push(format!("{ip}/{}", mask.map_or(32, u32::count_ones)));
                }
                ["inet6", ip, ..] if !ip.starts_with("fe80") && ip != "::1" => {
                    let len = t.iter().position(|w| *w == "prefixlen").and_then(|i| t.get(i + 1)).copied().unwrap_or("128");
                    addrs.push(format!("{}/{len}", ip.split('%').next().unwrap_or(ip)));
                }
                _ => {}
            }
        }
    }
    flush(&mut cur);
    Value::Array(res)
}

/// `lsof -nP` rows: `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME`, NAME like `*:22 (LISTEN)` or `[::1]:53`.
fn mac_listeners(lsof: &str) -> Value {
    lsof.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let n = t.len() - usize::from(t.last() == Some(&"(LISTEN)"));
            let (proto, name) = (t.get(n.checked_sub(2)?)?.to_lowercase(), *t.get(n - 1)?);
            // connected/unbound UDP sockets and ephemeral (dynamic range) ports aren't listeners
            if !(proto == "tcp" || proto == "udp") || name.contains("->") || name.ends_with(":*") {
                return None;
            }
            let v = listener(&proto, name, &t[0].replace("\\x20", " "));
            (proto == "tcp" || v["port"].as_u64() < Some(49152)).then_some(v)
        })
        .collect()
}

/// Running non-Apple launchd jobs from `launchctl list` (`PID Status Label`).
fn launchd_jobs(list: &str) -> Vec<String> {
    sorted_unique(
        list.lines()
            .filter_map(|l| match l.split_whitespace().collect::<Vec<_>>()[..] {
                [pid, _, label] if pid.parse::<u64>().is_ok() && !label.starts_with("com.apple.") && !label.starts_with("application.") => {
                    Some(label.to_string())
                }
                _ => None,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_powershell_command() {
        // [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("ab?"))
        assert_eq!(encode_command("ab?"), "YQBiAD8A");
        assert_eq!(encode_command("a"), "YQA=");
    }

    #[test]
    fn parses_linux() {
        let out = r#"
@@infra@@ platform
linux
@@infra@@ now
1700000000
@@infra@@ hostname
pve
@@infra@@ os_release
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
@@infra@@ kernel
6.8.12-4-pve
@@infra@@ uptime
12345.67 99999.00
@@infra@@ loadavg
0.10 0.20 0.30 1/234 5678
@@infra@@ nproc
8
@@infra@@ cpu_model
 Intel(R) Core(TM) i5
@@infra@@ meminfo
MemTotal:       16000000 kB
MemAvailable:    8000000 kB
SwapTotal:             0 kB
@@infra@@ disks
Mounted on Type 1B-blocks Used
/ ext4 100000 50000
@@infra@@ ip_addr
[{"ifname":"lo","addr_info":[]},{"ifname":"vmbr0","operstate":"UP","addr_info":[{"local":"10.0.0.5","prefixlen":24,"scope":"global"},{"local":"fe80::1","prefixlen":64,"scope":"link"}]}]
@@infra@@ ss
tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
udp   UNCONN 0 0 [::]:53 [::]:*
@@infra@@ services
ssh.service loaded active running OpenSSH
cron.service loaded active running Cron
@@infra@@ user_services otis
syncthing.service loaded active running Syncthing
dbus.service loaded active running D-Bus
@@infra@@ ufw
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
@@infra@@ updates
reboot_required
@@infra@@ apt_upgrades
Inst libc6 [2.36] (2.36-9 Debian-Security:12/stable-security [amd64])
Inst curl [7.88] (7.88-10 Debian:12/stable [amd64])
Conf libc6
@@infra@@ smart
@@infra@@ smart sda
{"model_name":"Samsung SSD","smart_status":{"passed":true},"power_on_time":{"hours":100},"temperature":{"current":35}}
@@infra@@ docker
@@infra@@ docker_ps
{"Names":"web","Image":"nginx","State":"running","Status":"Up 2h","Ports":"80/tcp","Labels":"a=b,com.docker.compose.project=site"}
@@infra@@ docker_compose
[{"Name":"site","Status":"running(1)","ConfigFiles":"/srv/site/compose.yml"}]
@@infra@@ tailscale
@@infra@@ tailscale_status
{"BackendState":"Running","Version":"1.76.1-abc","Self":{"TailscaleIPs":["100.64.0.1"],"DNSName":"pve.ts.net."},"Peer":{"k":{"HostName":"nas","DNSName":"nas.ts.net.","TailscaleIPs":["100.64.0.2"],"OS":"linux","Online":true}},"CurrentTailnet":{"Name":"me"}}
@@infra@@ tailscale_serve
{"Web":{"pve.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:8006"}}}}}
@@infra@@ proxmox
@@infra@@ pveversion
pve-manager/8.3.1/fb48e850ef9dde27 (running kernel: 6.8.12-4-pve)
@@infra@@ pve_qemu
[{"vmid":100,"name":"vm","status":"running","maxmem":2048,"maxdisk":10,"uptime":5}]
@@infra@@ pve_lxc
[{"vmid":"101","name":"ct","status":"stopped","maxmem":512,"maxdisk":4}]
@@infra@@ pve_config qemu 100
cores: 2
onboot: 1
ipconfig0: ip=10.0.0.10/24,gw=10.0.0.1
@@infra@@ pve_config lxc 101
onboot: 0
net0: name=eth0,bridge=vmbr0,ip=dhcp
@@infra@@ pve_storage
[{"storage":"local","type":"dir","total":100,"used":50,"content":"backup,iso","active":1}]
@@infra@@ pve_backups local
[{"volid":"local:backup/vzdump-qemu-100.vma.zst","vmid":100,"size":7,"ctime":9}]
@@infra@@ pve_backup_jobs
[{"id":"job1"}]
@@infra@@ pve_firewall
{"enable":1}
"#;
        let s = parse(out).unwrap();
        assert_eq!(s["os"], "Debian GNU/Linux 12 (bookworm)");
        assert_eq!(s["load"], json!([0.1, 0.2, 0.3]));
        assert_eq!(s["cpu"], json!({ "model": "Intel(R) Core(TM) i5", "count": 8 }));
        assert_eq!(s["memory"]["available"], 8_192_000_000u64);
        assert_eq!(s["disks"], json!([{ "mount": "/", "fstype": "ext4", "size": 100000, "used": 50000 }]));
        assert_eq!(s["addresses"], json!([{ "iface": "vmbr0", "state": "UP", "addrs": ["10.0.0.5/24"] }]));
        assert_eq!(
            s["listeners"],
            json!([{ "proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd" }, { "proto": "udp", "addr": "::", "port": 53, "process": "" }])
        );
        assert_eq!(s["services"], json!(["cron", "ssh"]));
        assert_eq!(s["user_services"], json!({ "otis": ["syncthing"] }));
        assert_eq!(s["firewall"], json!({ "kind": "ufw", "active": true, "rules": ["22/tcp                     ALLOW       Anywhere"] }));
        assert_eq!(s["updates"], json!({ "pending": 2, "security": 1, "reboot_required": true }));
        assert_eq!(s["smart"][0], json!({ "device": "sda", "model": "Samsung SSD", "passed": true, "power_on_hours": 100, "temp": 35 }));
        assert_eq!(s["docker"]["containers"][0]["project"], "site");
        assert_eq!(s["docker"]["version"], Value::Null);
        assert_eq!(s["tailscale"]["serve"], json!([{ "url": "https://pve.ts.net/", "target": "http://127.0.0.1:8006" }]));
        assert_eq!(s["tailscale"]["version"], "1.76.1");
        assert_eq!(s["tailscale"]["peers"][0]["dns"], "nas.ts.net");
        let pve = &s["proxmox"];
        assert_eq!(pve["version"], "8.3.1");
        assert_eq!(pve["guests"][0], json!({ "vmid": 100, "name": "vm", "status": "running", "type": "qemu", "cores": 2, "memory": 2048, "disk": 10, "onboot": true, "uptime": 5, "ip": "10.0.0.10" }));
        assert_eq!(pve["guests"][1]["vmid"], 101);
        assert_eq!(pve["guests"][1]["onboot"], false);
        assert_eq!(pve["guests"][1]["ip"], Value::Null);
        assert_eq!(pve["backups"][0]["vmid"], 100);
        assert_eq!((pve["backup_jobs"].clone(), pve["firewall_enabled"].clone()), (json!(1), json!(true)));
        assert!(s.get("errors").is_none());
    }

    #[test]
    fn parses_macos_parts() {
        let df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk3s1s1 100 10 90 10% /\nmap auto_home 0 0 0 100% /System/Volumes/Data/home\n/dev/disk3s6 100 1 90 1% /System/Volumes/VM\n/dev/disk3s5 100 60 90 60% /System/Volumes/Data\n/dev/disk5s1 50 5 45 10% /Volumes/My Disk";
        let mount = "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\nmap auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)\n/dev/disk3s6 on /System/Volumes/VM (apfs, local, nobrowse)\n/dev/disk3s5 on /System/Volumes/Data (apfs, local, nobrowse)\n/dev/disk5s1 on /Volumes/My Disk (exfat, local)";
        let mounts: Vec<_> = mac_disks(df, mount).as_array().unwrap().iter().map(|d| d["mount"].as_str().unwrap().to_string()).collect();
        assert_eq!(mounts, ["/", "/System/Volumes/Data", "/Volumes/My Disk"]);

        let ifconfig = "lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\nen0: flags=8863<UP,BROADCAST> mtu 1500\n\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x6\n\tinet 10.0.0.200 netmask 0xffffff00 broadcast 10.0.0.255\n\tinet6 fd00::5 prefixlen 64 autoconf\n\tstatus: active\nen1: flags=8863<UP> mtu 1500\n\tstatus: inactive\nutun4: flags=8051<UP,POINTOPOINT> mtu 1280\n\tinet 100.64.0.3 --> 100.64.0.3 netmask 0xffffffff";
        assert_eq!(
            mac_addresses(ifconfig),
            json!([{ "iface": "en0", "state": "UP", "addrs": ["10.0.0.200/24", "fd00::5/64"] }, { "iface": "utun4", "state": "UP", "addrs": ["100.64.0.3/32"] }])
        );

        let lsof = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nControl\\x20Center 1 u 1u IPv4 0x1 0t0 TCP *:7000 (LISTEN)\nsshd 2 root 3u IPv6 0x2 0t0 TCP [::1]:22 (LISTEN)\ncloudd 3 u 1u IPv4 0x3 0t0 UDP 10.0.0.2:5000->1.1.1.1:443\nmDNS 4 u 1u IPv4 0x4 0t0 UDP *:5353\nfoo 5 u 1u IPv4 0x5 0t0 UDP *:60000";
        assert_eq!(
            mac_listeners(lsof),
            json!([{ "proto": "tcp", "addr": "*", "port": 7000, "process": "Control Center" }, { "proto": "tcp", "addr": "::1", "port": 22, "process": "sshd" }, { "proto": "udp", "addr": "*", "port": 5353, "process": "mDNS" }])
        );

        assert_eq!(launchd_jobs("PID\tStatus\tLabel\n12\t0\tcom.apple.x\n-\t0\tcom.foo.idle\n34\t0\tcom.docker.vmnetd\n56\t0\tapplication.com.foo.1"), ["com.docker.vmnetd"]);
        assert_eq!(mac_swap("total = 2048.00M  used = 1.00M  free = 2047.00M  (encrypted)"), 2 << 30);
        let vm = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 10.\nPages wired down: 100.\nPages purgeable: 50.\nAnonymous pages: 250.\nPages occupied by compressor: 50.";
        assert_eq!(mac_available(vm, 1000 * 16384), (1000 - 350) * 16384);
    }

    #[test]
    fn parses_windows_json_sections() {
        let out = "\r\n@@infra@@ platform\r\nwindows\r\n@@infra@@ json collected_at\r\n1700000000\r\n@@infra@@ json os\r\n\"Microsoft Windows 11 Pro 23H2\"\r\n@@infra@@ json listeners\r\n[{\"proto\":\"tcp\",\"addr\":\"0.0.0.0\",\"port\":445,\"process\":\"System\"},{\"proto\":\"tcp\",\"addr\":\"::\",\"port\":135,\"process\":\"svchost\"}]\r\n@@infra@@ json bogus\r\n1\r\n@@infra@@ json disks\r\n[oops\r\n";
        let s = parse(out).unwrap();
        assert_eq!(s["platform"], "windows");
        assert_eq!(s["collected_at"], 1700000000);
        assert_eq!(s["os"], "Microsoft Windows 11 Pro 23H2");
        assert_eq!(s["listeners"][0]["port"], 135);
        assert!(s.get("bogus").is_none() && s["proxmox"].is_null() && s["docker"].is_null());
        assert!(s["errors"]["disks"].as_str().unwrap().starts_with("json disks:"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("sudo: a password is required").unwrap_err().contains("a password is required"));
    }

    /// Runs the collector for this machine's OS locally (no root, so some sections come back empty).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn local_collector() {
        let script = if cfg!(target_os = "macos") { MACOS } else { LINUX };
        let mut child = Command::new("sh").arg("-s").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        let s = parse(&String::from_utf8_lossy(&out.stdout)).unwrap();
        assert!(s.get("errors").is_none(), "{}", s["errors"]);
        assert!(s["hostname"].as_str().is_some_and(|h| !h.is_empty()));
        assert!(s["memory"]["total"].as_u64() > Some(0) && s["cpu"]["count"].as_u64() > Some(0));
        assert!(s["disks"].as_array().is_some_and(|d| !d.is_empty()), "{}", s["disks"]);
        assert!(s["addresses"].as_array().is_some_and(|a| !a.is_empty()), "{}", s["addresses"]);
    }
}
