use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use rusqlite::{params, Connection, OpenFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::{self, File, OpenOptions}, io::Write, path::{Path, PathBuf}};
use uuid::Uuid;
use crate::Report;

pub struct Store {
    pub db: Connection,
    path: PathBuf,
    quota: u64,
    used: u64,
    // Enforce a single writer across processes, including after restart.
    _lock: File,
}

#[cfg(unix)]
fn private_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}
#[cfg(not(unix))]
fn private_file(_: &mut OpenOptions) {}

impl Store {
    pub fn new(path: &Path, quota: u64) -> Result<Self> {
        if let Ok(info) = path.symlink_metadata() {
            anyhow::ensure!(info.is_dir() && !info.file_type().is_symlink(), "data must be a real directory, not a symlink");
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                anyhow::ensure!(info.permissions().mode() & 0o077 == 0, "existing data directory must be private (chmod 700 before starting)");
            }
        }
        if !path.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)] {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(path)?;
        }
        // Advisory locks are held by the OS, released on crashes. No stale lock deletion.
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        private_file(&mut options);
        let lock = options.open(path.join("writer.lock"))?;
        lock.try_lock().context("another collector owns this evidence directory")?;
        let db = Connection::open(path.join("events.sqlite3"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, time TEXT NOT NULL, peer TEXT, local TEXT,
            metadata TEXT NOT NULL, raw_file TEXT, raw_sha256 TEXT, raw_bytes INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS events_time_id ON events(time,id);")?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            for name in ["events.sqlite3", "events.sqlite3-wal", "events.sqlite3-shm"] {
                let file = path.join(name);
                if file.exists() { fs::set_permissions(file, fs::Permissions::from_mode(0o600))?; }
            }
        }
        let used = fs::read_dir(path)?.try_fold(0u64, |total, entry| -> Result<u64> {
            let info = entry?.metadata()?;
            Ok(total.saturating_add(if info.is_file() { info.len() } else { 0 }))
        })?;
        Ok(Self { db, path: path.to_owned(), quota, used, _lock: lock })
    }

    pub fn save(&mut self, raw: &[u8], metadata: &Value, peer: Value, local: Value) -> Result<Value> {
        let id = Uuid::new_v4().simple().to_string();
        // Keep the legacy UTC +00:00 suffix so mixed old/new text timestamps
        // retain chronological ordering; fix fractional precision for new rows.
        let stamp = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, false);
        let encoded = serde_json::to_string(metadata)?;
        let cost = raw.len() as u64 + encoded.len() as u64 + 16384;
        if self.used.saturating_add(cost) > self.quota {
            bail!("capture quota reached; collection stopped");
        }
        let filename = format!("{id}.raw");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        private_file(&mut options);
        let mut file = options.open(self.path.join(&filename))?;
        file.write_all(raw)?;
        file.sync_all()?;
        // Persist the new directory entry before committing the index row.
        #[cfg(unix)]
        File::open(&self.path)?.sync_all()?;
        let hash = format!("{:x}", Sha256::digest(raw));
        self.db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)", params![
            id, stamp, peer.to_string(), local.to_string(), encoded, filename, hash, raw.len() as i64])?;
        self.used += cost;
        // Raw headers/credentials stay in restricted evidence, not stdout.
        Ok(json!({"id":id,"time":stamp,"peer":peer,"bytes":raw.len(),
            "event":"http.request","method":metadata["method"],"target":metadata["target"],
            "signals":metadata["signals"],"complete":metadata["complete"],"error":metadata["error"]}))
    }
}

pub fn open_readonly(path: &Path) -> Result<Connection> {
    let db = Connection::open_with_flags(path.join("events.sqlite3"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(std::time::Duration::from_secs(2))?;
    Ok(db)
}

pub fn validate_http_metadata(meta: &Value, peer: &Value) -> Result<()> {
    anyhow::ensure!(meta.is_object() && meta["complete"].is_boolean(), "invalid HTTP metadata object/completeness");
    for key in ["method", "target", "http_version", "error"] {
        anyhow::ensure!(meta[key].is_null() || meta[key].is_string(), "invalid HTTP metadata field: {key}");
    }
    anyhow::ensure!(meta["tls"].is_null() || meta["tls"].is_boolean(), "invalid TLS flag");
    if let Some(signals) = meta.get("signals") {
        anyhow::ensure!(signals.as_array().is_some_and(|items| items.len() <= 64 && items.iter().all(Value::is_string)), "invalid HTTP signals");
    }
    let endpoint = peer.as_array().context("HTTP peer is not an endpoint")?;
    anyhow::ensure!(endpoint.len() == 2 && endpoint[0].as_str().is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok())
        && endpoint[1].as_u64().is_some_and(|port| port <= 65535), "invalid HTTP peer endpoint");
    Ok(())
}

pub fn report(args: Report) -> Result<()> {
    let db = open_readonly(&args.data)?;
    let mut stmt = db.prepare("SELECT id,time,peer,CASE WHEN length(metadata)<=1048576 THEN metadata ELSE NULL END,raw_bytes FROM events ORDER BY time DESC,id DESC LIMIT ?")?;
    let rows = stmt.query_map([args.limit], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?, r.get::<_, i64>(4)?)))?;
    let mut recent = Vec::new();
    let mut count = 0;
    let mut retained_bytes = 0usize;
    let mut truncated = false;
    let mut signals = BTreeMap::<String, usize>::new();
    for row in rows {
        let (id, stamp, peer, meta, bytes) = row?;
        let encoded = meta.as_deref().with_context(|| format!("HTTP record {id}: metadata exceeds 1 MiB"))?;
        let mut meta: Value = serde_json::from_str(encoded).with_context(|| format!("HTTP record {id}: invalid metadata JSON"))?;
        let peer: Value = serde_json::from_str(&peer).with_context(|| format!("HTTP record {id}: invalid peer JSON"))?;
        validate_http_metadata(&meta, &peer).with_context(|| format!("HTTP record {id}: invalid metadata/endpoint"))?;
        count += 1;
        if let Some(items) = meta["signals"].as_array() {
            for signal in items.iter().filter_map(Value::as_str) {
                anyhow::ensure!(signals.len() < 1024 || signals.contains_key(signal), "HTTP signal cardinality exceeded");
                *signals.entry(signal.to_owned()).or_default() += 1;
            }
        }
        if recent.len() < args.recent as usize {
            meta["time"] = json!(stamp);
            meta["peer"] = peer;
            meta["bytes"] = json!(bytes);
            // Explicit raw inspection is separate from routine reporting.
            meta.as_object_mut().context("invalid metadata object")?.remove("headers");
            let bytes = serde_json::to_vec(&meta)?.len();
            if retained_bytes.saturating_add(bytes) <= 16 * 1024 * 1024 && !truncated {
                retained_bytes += bytes;
                recent.push(meta);
            } else { truncated = true; }
        }
    }
    println!("{}", serde_json::to_string_pretty(&json!({"sample_limit":args.limit,"events_in_sample":count,"recent_truncated":truncated,"signals":signals,"recent":recent}))?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_schema_bytes_and_sha256_across_restart() {
        let root=tempfile::tempdir().unwrap();
        // Let the collector create its private evidence directory. TempDir's
        // own permissions depend on the platform/version and process umask.
        let data=root.path().join("evidence");
        let raw=b"POST / HTTP/1.1\r\n\r\n\0\xff";
        let event={
            let mut store=Store::new(data.as_path(),1000000).unwrap();
            store.save(raw,&json!({"complete":true}),json!(["198.51.100.7",1234]),json!(["127.0.0.1",8080])).unwrap()
        };
        let db=open_readonly(data.as_path()).unwrap();
        let (filename,hash):(String,String)=db.query_row("SELECT raw_file,raw_sha256 FROM events WHERE id=?",[event["id"].as_str().unwrap()],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(fs::read(data.as_path().join(filename)).unwrap(),raw);
        assert_eq!(hash,format!("{:x}",Sha256::digest(raw)));
        assert!(db.execute("DELETE FROM events",[]).is_err());
    }
    #[test]
    fn quota_fails_before_new_capture_and_writer_lock_prevents_two_sensors() {
        let root=tempfile::tempdir().unwrap();
        // Let the collector create its private evidence directory. TempDir's
        // own permissions depend on the platform/version and process umask.
        let data=root.path().join("evidence");
        let mut store=Store::new(data.as_path(),1).unwrap();
        assert!(Store::new(data.as_path(),1000000).is_err());
        assert!(store.save(b"x",&json!({}),json!(null),json!(null)).is_err());
        let count:i64=store.db.query_row("SELECT count(*) FROM events",[],|r|r.get(0)).unwrap();
        assert_eq!(count,0);
    }
    #[test]
    fn report_typo_does_not_create_a_database() {
        let root=tempfile::tempdir().unwrap();
        // Let the collector create its private evidence directory. TempDir's
        // own permissions depend on the platform/version and process umask.
        let data=root.path().join("evidence");
        assert!(open_readonly(data.as_path()).is_err());
        assert!(!data.as_path().join("events.sqlite3").exists());
    }
    #[test]
    fn report_rejects_non_object_metadata_even_without_recent_rows() {
        let root=tempfile::tempdir().unwrap();
        // Let the collector create its private evidence directory. TempDir's
        // own permissions depend on the platform/version and process umask.
        let data=root.path().join("evidence");
        let mut store=Store::new(data.as_path(),1000000).unwrap();
        store.save(b"x",&json!([]),json!(["198.51.100.7",42]),json!(null)).unwrap();
        assert!(report(Report {data:data.as_path().to_owned(),limit:100,recent:0}).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn creates_private_directory_and_rejects_an_existing_public_one() {
        use std::os::unix::fs::PermissionsExt;
        let root=tempfile::tempdir().unwrap();
        let data=root.path().join("evidence");
        let store=Store::new(&data,1000000).unwrap();
        assert_eq!(fs::metadata(&data).unwrap().permissions().mode() & 0o777,0o700);
        drop(store);
        fs::set_permissions(&data,fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::new(&data,1000000).is_err());
        assert_eq!(fs::metadata(&data).unwrap().permissions().mode() & 0o777,0o755);
    }

}
