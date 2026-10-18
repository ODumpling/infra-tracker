use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager};
use tauri_plugin_opener::OpenerExt;

const COLLECTOR: &str = include_str!("../collector.py");
// Runs the collector as root: directly if already root, otherwise via passwordless sudo.
const REMOTE_CMD: &str = r#"if [ "$(id -u)" = 0 ]; then exec python3 -; else exec sudo -n python3 -; fi"#;

#[derive(Serialize, Deserialize, Clone)]
struct Host {
    id: String,
    name: String,
    /// ssh destination: alias from ~/.ssh/config or user@host
    ssh: String,
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    role: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    hosts: Vec<Host>,
    #[serde(default)]
    docs_dir: Option<String>,
    /// 0 = manual only
    #[serde(default)]
    scan_interval_min: u32,
    #[serde(default = "default_keep")]
    keep_snapshots: usize,
}

fn default_keep() -> usize {
    100
}

fn default_config(app: &AppHandle) -> Config {
    let docs = app.path().home_dir().ok().map(|h| h.join("Code/Infrastructure").to_string_lossy().into_owned());
    Config {
        hosts: vec![],
        docs_dir: docs,
        scan_interval_min: 0,
        keep_snapshots: default_keep(),
    }
}

fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn config_file(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(data_dir(app)?.join("config.json"))
}

fn host_dir(app: &AppHandle, id: &str) -> Result<PathBuf, String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') || id.starts_with('.') {
        return Err(format!("invalid host id: {id}"));
    }
    let dir = data_dir(app)?.join("snapshots").join(id);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn read_json(path: &PathBuf) -> Option<Value> {
    fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok())
}

fn write_json(path: &PathBuf, v: &impl Serialize) -> Result<(), String> {
    let s = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    fs::write(path, s).map_err(|e| e.to_string())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Snapshot timestamps for a host, newest first.
fn snapshot_times(app: &AppHandle, id: &str) -> Result<Vec<u64>, String> {
    let mut times: Vec<u64> = fs::read_dir(host_dir(app, id)?)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".json")?.parse().ok())
        .collect();
    times.sort_unstable_by(|a, b| b.cmp(a));
    Ok(times)
}

#[tauri::command]
fn get_config(app: AppHandle) -> Result<Config, String> {
    let path = config_file(&app)?;
    if let Some(v) = read_json(&path) {
        return serde_json::from_value(v).map_err(|e| format!("config.json: {e}"));
    }
    let cfg = default_config(&app);
    write_json(&path, &cfg)?;
    Ok(cfg)
}

#[tauri::command]
fn save_config(app: AppHandle, config: Config) -> Result<(), String> {
    for h in &config.hosts {
        host_dir(&app, &h.id)?;
    }
    write_json(&config_file(&app)?, &config)
}

#[tauri::command]
async fn scan_host(app: AppHandle, id: String) -> Result<Value, String> {
    let cfg = get_config(app.clone())?;
    let host = cfg.hosts.iter().find(|h| h.id == id).cloned().ok_or("unknown host")?;
    let dir = host_dir(&app, &id)?;
    let result = tauri::async_runtime::spawn_blocking(move || collect(&host.ssh, false))
        .await
        .map_err(|e| e.to_string())?;
    let err_file = dir.join("error");
    match result {
        Ok(snapshot) => {
            let ts = snapshot.get("collected_at").and_then(Value::as_u64).unwrap_or_else(now);
            write_json(&dir.join(format!("{ts}.json")), &snapshot)?;
            let _ = fs::remove_file(err_file);
            for old in snapshot_times(&app, &id)?.into_iter().skip(cfg.keep_snapshots.max(2)) {
                let _ = fs::remove_file(dir.join(format!("{old}.json")));
            }
            Ok(snapshot)
        }
        Err(msg) => {
            write_json(&err_file, &json!({ "at": now(), "message": msg }))?;
            Err(msg)
        }
    }
}

/// Scan an ssh target that isn't configured yet (add-host flow). Nothing is saved.
#[tauri::command]
async fn probe_host(ssh: String) -> Result<Value, String> {
    let ssh = ssh.trim().to_string();
    if ssh.is_empty() || ssh.starts_with('-') || ssh.chars().any(char::is_whitespace) {
        return Err("invalid ssh target".into());
    }
    tauri::async_runtime::spawn_blocking(move || collect(&ssh, true)).await.map_err(|e| e.to_string())?
}

/// Append a host to the config and store the probe snapshot as its first scan.
#[tauri::command]
fn add_host(app: AppHandle, host: Host, snapshot: Value) -> Result<(), String> {
    let mut cfg = get_config(app.clone())?;
    if host.name.trim().is_empty() || host.ssh.trim().is_empty() {
        return Err("name and ssh are required".into());
    }
    if cfg.hosts.iter().any(|h| h.id == host.id) {
        return Err(format!("host id already exists: {}", host.id));
    }
    let dir = host_dir(&app, &host.id)?;
    let ts = snapshot.get("collected_at").and_then(Value::as_u64).unwrap_or_else(now);
    write_json(&dir.join(format!("{ts}.json")), &snapshot)?;
    cfg.hosts.push(host);
    write_json(&config_file(&app)?, &cfg)
}

/// `accept_new`: trust-on-first-use for hosts not yet in known_hosts (only for explicit add-host probes).
fn collect(dest: &str, accept_new: bool) -> Result<Value, String> {
    let mut child = Command::new("ssh")
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3"])
        .args(if accept_new { &["-o", "StrictHostKeyChecking=accept-new"][..] } else { &[] })
        .arg("--")
        .arg(dest)
        .arg(REMOTE_CMD)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to run ssh: {e}"))?;
    child.stdin.take().ok_or("no stdin")?.write_all(COLLECTOR.as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if err.contains("agent") && (err.contains("communication with agent failed") || err.contains("agent refused")) {
            return Err(format!("{err}\n(SSH agent refused — is 1Password unlocked?)"));
        }
        return Err(if err.is_empty() { format!("ssh exited with {}", out.status) } else { err });
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("bad collector output: {e}"))
}

/// Latest + previous snapshot and last error for every configured host.
#[tauri::command]
fn load_state(app: AppHandle) -> Result<Map<String, Value>, String> {
    let cfg = get_config(app.clone())?;
    let mut state = Map::new();
    for h in cfg.hosts {
        let dir = host_dir(&app, &h.id)?;
        let times = snapshot_times(&app, &h.id)?;
        let snap = |i: usize| times.get(i).and_then(|t| read_json(&dir.join(format!("{t}.json"))));
        state.insert(h.id.clone(), json!({
            "latest": snap(0),
            "previous": snap(1),
            "error": read_json(&dir.join("error")),
            "history": times,
        }));
    }
    Ok(state)
}

#[tauri::command]
fn load_snapshot(app: AppHandle, id: String, ts: u64) -> Result<Value, String> {
    read_json(&host_dir(&app, &id)?.join(format!("{ts}.json"))).ok_or_else(|| "snapshot not found".into())
}

#[tauri::command]
fn get_notes(app: AppHandle) -> Result<Value, String> {
    Ok(read_json(&data_dir(&app)?.join("notes.json")).unwrap_or_else(|| json!({})))
}

#[tauri::command]
fn save_notes(app: AppHandle, notes: Value) -> Result<(), String> {
    write_json(&data_dir(&app)?.join("notes.json"), &notes)
}

#[tauri::command]
fn export_markdown(app: AppHandle, content: String) -> Result<String, String> {
    let cfg = get_config(app.clone())?;
    let dir = match cfg.docs_dir.filter(|d| !d.trim().is_empty()) {
        Some(d) => PathBuf::from(d),
        None => data_dir(&app)?,
    };
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("INVENTORY.md");
    fs::write(&path, content).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}

#[tauri::command]
fn reveal(app: AppHandle, path: Option<String>) -> Result<(), String> {
    let p = match path {
        Some(p) => PathBuf::from(p),
        None => config_file(&app)?,
    };
    app.opener().reveal_item_in_dir(p).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            get_config, save_config, scan_host, probe_host, add_host, load_state, load_snapshot, get_notes, save_notes, export_markdown, reveal
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    /// Live scan through ssh: `INFRA_TEST_HOST=pve cargo test -- --ignored`
    #[test]
    #[ignore]
    fn collect_live() {
        let host = std::env::var("INFRA_TEST_HOST").unwrap_or_else(|_| "pve".into());
        let snap = super::collect(&host, false).expect("collect failed");
        assert!(snap["hostname"].is_string());
        assert!(snap["disks"].as_array().is_some_and(|d| !d.is_empty()));
    }
}
