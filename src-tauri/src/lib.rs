use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_opener::OpenerExt;

mod collect;
use collect::collect;

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

fn check_id(id: &str) -> Result<(), String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') || id.starts_with('.') {
        return Err(format!("invalid host id: {id}"));
    }
    Ok(())
}

/// Snapshots, scan errors and notes live in `infra.db`; config stays in editable `config.json`.
struct Db(Mutex<Connection>);

impl Db {
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn open_db(dir: &Path) -> Result<Connection, String> {
    let conn = Connection::open(dir.join("infra.db")).map_err(err)?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         CREATE TABLE IF NOT EXISTS snapshots (
             host TEXT NOT NULL,
             ts   INTEGER NOT NULL,
             data TEXT NOT NULL,
             PRIMARY KEY (host, ts)
         ) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS scan_errors (
             host    TEXT PRIMARY KEY,
             at      INTEGER NOT NULL,
             message TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS notes (
             host TEXT PRIMARY KEY,
             body TEXT NOT NULL
         );",
    )
    .map_err(err)?;
    import_legacy(&conn, dir)?;
    Ok(conn)
}

/// One-time import of the old JSON-file layout (`snapshots/<host>/<ts>.json`, `snapshots/<host>/error`, `notes.json`).
/// Imported files are renamed (`snapshots.imported`, `notes.json.imported`), not deleted.
fn import_legacy(conn: &Connection, dir: &Path) -> Result<(), String> {
    let snaps = dir.join("snapshots");
    if let Ok(hosts) = fs::read_dir(&snaps) {
        for host in hosts.filter_map(Result::ok) {
            let Some(id) = host.file_name().to_str().map(str::to_owned) else { continue };
            for f in fs::read_dir(host.path()).into_iter().flatten().filter_map(Result::ok) {
                let path = f.path();
                let Some(v) = read_json(&path) else { continue };
                if let Some(ts) = f.file_name().to_str().and_then(|n| n.strip_suffix(".json")?.parse::<u64>().ok()) {
                    insert_snapshot(conn, &id, ts, &v)?;
                } else if f.file_name() == "error" {
                    let msg = v.get("message").and_then(Value::as_str).unwrap_or_default();
                    set_error(conn, &id, v.get("at").and_then(Value::as_u64).unwrap_or(0), msg)?;
                }
            }
        }
        fs::rename(&snaps, dir.join("snapshots.imported")).map_err(err)?;
    }
    let notes = dir.join("notes.json");
    if let Some(Value::Object(m)) = read_json(&notes) {
        for (id, body) in m {
            conn.execute("INSERT OR REPLACE INTO notes (host, body) VALUES (?1, ?2)", params![id, body.as_str().unwrap_or_default()])
                .map_err(err)?;
        }
        fs::rename(&notes, dir.join("notes.json.imported")).map_err(err)?;
    }
    Ok(())
}

fn insert_snapshot(conn: &Connection, id: &str, ts: u64, snapshot: &Value) -> Result<(), String> {
    conn.execute("INSERT OR REPLACE INTO snapshots (host, ts, data) VALUES (?1, ?2, ?3)", params![id, ts as i64, snapshot.to_string()])
        .map_err(err)?;
    Ok(())
}

fn set_error(conn: &Connection, id: &str, at: u64, message: &str) -> Result<(), String> {
    conn.execute("INSERT OR REPLACE INTO scan_errors (host, at, message) VALUES (?1, ?2, ?3)", params![id, at as i64, message])
        .map_err(err)?;
    Ok(())
}

fn get_snapshot(conn: &Connection, id: &str, ts: u64) -> Result<Option<Value>, String> {
    let data: Option<String> = conn
        .query_row("SELECT data FROM snapshots WHERE host = ?1 AND ts = ?2", params![id, ts as i64], |r| r.get(0))
        .optional()
        .map_err(err)?;
    data.map(|d| serde_json::from_str(&d).map_err(err)).transpose()
}

fn read_json(path: &Path) -> Option<Value> {
    fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok())
}

fn write_json(path: &Path, v: &impl Serialize) -> Result<(), String> {
    let s = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    fs::write(path, s).map_err(|e| e.to_string())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Snapshot timestamps for a host, newest first.
fn snapshot_times(conn: &Connection, id: &str) -> Result<Vec<u64>, String> {
    let mut stmt = conn.prepare_cached("SELECT ts FROM snapshots WHERE host = ?1 ORDER BY ts DESC").map_err(err)?;
    let rows = stmt.query_map([id], |r| r.get::<_, i64>(0)).map_err(err)?;
    rows.map(|r| r.map(|t| t as u64).map_err(err)).collect()
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
        check_id(&h.id)?;
    }
    write_json(&config_file(&app)?, &config)
}

#[tauri::command]
async fn scan_host(app: AppHandle, db: State<'_, Db>, id: String) -> Result<Value, String> {
    let cfg = get_config(app.clone())?;
    let host = cfg.hosts.iter().find(|h| h.id == id).cloned().ok_or("unknown host")?;
    let result = tauri::async_runtime::spawn_blocking(move || collect(&host.ssh, false))
        .await
        .map_err(|e| e.to_string())?;
    let mut conn = db.lock();
    match result {
        Ok(snapshot) => {
            let ts = snapshot.get("collected_at").and_then(Value::as_u64).unwrap_or_else(now);
            let tx = conn.transaction().map_err(err)?;
            insert_snapshot(&tx, &id, ts, &snapshot)?;
            tx.execute("DELETE FROM scan_errors WHERE host = ?1", [&id]).map_err(err)?;
            tx.execute(
                "DELETE FROM snapshots WHERE host = ?1 AND ts NOT IN (SELECT ts FROM snapshots WHERE host = ?1 ORDER BY ts DESC LIMIT ?2)",
                params![id, cfg.keep_snapshots.max(2) as i64],
            )
            .map_err(err)?;
            tx.commit().map_err(err)?;
            Ok(snapshot)
        }
        Err(msg) => {
            set_error(&conn, &id, now(), &msg)?;
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
fn add_host(app: AppHandle, db: State<'_, Db>, host: Host, snapshot: Value) -> Result<(), String> {
    let mut cfg = get_config(app.clone())?;
    if host.name.trim().is_empty() || host.ssh.trim().is_empty() {
        return Err("name and ssh are required".into());
    }
    if cfg.hosts.iter().any(|h| h.id == host.id) {
        return Err(format!("host id already exists: {}", host.id));
    }
    check_id(&host.id)?;
    let ts = snapshot.get("collected_at").and_then(Value::as_u64).unwrap_or_else(now);
    insert_snapshot(&db.lock(), &host.id, ts, &snapshot)?;
    cfg.hosts.push(host);
    write_json(&config_file(&app)?, &cfg)
}

/// Latest + previous snapshot and last error for every configured host.
#[tauri::command]
fn load_state(app: AppHandle, db: State<'_, Db>) -> Result<Map<String, Value>, String> {
    let cfg = get_config(app.clone())?;
    let conn = db.lock();
    let mut state = Map::new();
    for h in cfg.hosts {
        let times = snapshot_times(&conn, &h.id)?;
        let snap = |i: usize| times.get(i).map(|&t| get_snapshot(&conn, &h.id, t)).transpose().map(Option::flatten);
        let error = conn
            .query_row("SELECT at, message FROM scan_errors WHERE host = ?1", [&h.id], |r| {
                Ok(json!({ "at": r.get::<_, i64>(0)?, "message": r.get::<_, String>(1)? }))
            })
            .optional()
            .map_err(err)?;
        state.insert(h.id.clone(), json!({
            "latest": snap(0)?,
            "previous": snap(1)?,
            "error": error,
            "history": times,
        }));
    }
    Ok(state)
}

#[tauri::command]
fn load_snapshot(db: State<'_, Db>, id: String, ts: u64) -> Result<Value, String> {
    get_snapshot(&db.lock(), &id, ts)?.ok_or_else(|| "snapshot not found".into())
}

#[tauri::command]
fn get_notes(db: State<'_, Db>) -> Result<Map<String, Value>, String> {
    let conn = db.lock();
    let mut stmt = conn.prepare("SELECT host, body FROM notes").map_err(err)?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, Value::String(r.get(1)?)))).map_err(err)?;
    rows.map(|r| r.map_err(err)).collect()
}

#[tauri::command]
fn save_notes(db: State<'_, Db>, notes: Map<String, Value>) -> Result<(), String> {
    let mut conn = db.lock();
    let tx = conn.transaction().map_err(err)?;
    tx.execute("DELETE FROM notes", []).map_err(err)?;
    for (id, body) in &notes {
        if let Some(b) = body.as_str().filter(|b| !b.trim().is_empty()) {
            tx.execute("INSERT INTO notes (host, body) VALUES (?1, ?2)", params![id, b]).map_err(err)?;
        }
    }
    tx.commit().map_err(err)
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
        .setup(|app| {
            let conn = open_db(&data_dir(app.handle())?)?;
            app.manage(Db(Mutex::new(conn)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_config, save_config, scan_host, probe_host, add_host, load_state, load_snapshot, get_notes, save_notes, export_markdown, reveal
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_legacy_json() {
        let dir = std::env::temp_dir().join(format!("infra-tracker-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("snapshots/pve")).unwrap();
        write_json(&dir.join("snapshots/pve/100.json"), &json!({ "hostname": "pve", "collected_at": 100 })).unwrap();
        write_json(&dir.join("snapshots/pve/200.json"), &json!({ "hostname": "pve", "collected_at": 200 })).unwrap();
        write_json(&dir.join("snapshots/pve/error"), &json!({ "at": 300, "message": "boom" })).unwrap();
        write_json(&dir.join("notes.json"), &json!({ "pve": "home lab" })).unwrap();

        let conn = open_db(&dir).unwrap();
        assert_eq!(snapshot_times(&conn, "pve").unwrap(), vec![200, 100]);
        assert_eq!(get_snapshot(&conn, "pve", 100).unwrap().unwrap()["collected_at"], 100);
        let msg: String = conn.query_row("SELECT message FROM scan_errors WHERE host = 'pve'", [], |r| r.get(0)).unwrap();
        assert_eq!(msg, "boom");
        let body: String = conn.query_row("SELECT body FROM notes WHERE host = 'pve'", [], |r| r.get(0)).unwrap();
        assert_eq!(body, "home lab");
        assert!(dir.join("snapshots.imported").exists() && !dir.join("snapshots").exists());
        drop(conn);
        // reopening doesn't re-import or fail
        assert_eq!(snapshot_times(&open_db(&dir).unwrap(), "pve").unwrap().len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Live scan through ssh: `INFRA_TEST_HOST=pve cargo test -- --ignored`
    #[test]
    #[ignore]
    fn collect_live() {
        let host = std::env::var("INFRA_TEST_HOST").unwrap_or_else(|_| "pve".into());
        let snap = collect(&host, false).expect("collect failed");
        assert!(snap["hostname"].is_string());
        assert!(snap["disks"].as_array().is_some_and(|d| !d.is_empty()));
    }
}
