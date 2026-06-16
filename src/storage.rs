use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};

use crate::types::{AppResult, ManifestEntry};

const LEGACY_TSV_MIGRATION_KEY: &str = "legacy_tsv_migrated";
const DEFAULT_DB_FILE: &str = concat!("state", ".db");

pub fn ensure_layout(root: &Path) -> AppResult<()> {
    for rel in ["chunks", "manifests", "state", "keys", "tmp", "remote_sync"] {
        fs::create_dir_all(root.join(rel)).map_err(|e| format!("create dir {rel}: {e}"))?;
    }
    Ok(())
}

pub fn default_db_path(root: &Path) -> PathBuf {
    env::var("APP_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("state").join(DEFAULT_DB_FILE))
}

pub struct StateStore {
    conn: Connection,
    archive_key: String,
}

impl StateStore {
    pub fn open(root: &Path) -> AppResult<Self> {
        fs::create_dir_all(root.join("state")).map_err(|e| format!("create state dir: {e}"))?;
        let archive_key = fs::canonicalize(root)
            .map_err(|e| format!("canonicalize archive root {}: {e}", root.display()))?
            .to_string_lossy()
            .to_string();
        let db_path = default_db_path(root);
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create state db parent: {e}"))?;
        }
        let conn = Connection::open(&db_path)
            .map_err(|e| format!("open state db {}: {e}", db_path.display()))?;
        let mut store = Self { conn, archive_key };
        store.init_schema()?;
        store.migrate_legacy_tsv(root)?;
        Ok(store)
    }

    pub fn checkpoint(&self, path: &str) -> AppResult<Option<u64>> {
        let offset = self
            .conn
            .query_row(
                "SELECT offset FROM checkpoints WHERE archive_key = ?1 AND path = ?2",
                params![&self.archive_key, path],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|e| format!("query checkpoint: {e}"))?;
        offset.map(i64_to_u64).transpose()
    }

    pub fn has_seen_id(&self, record_id: &str) -> AppResult<bool> {
        let exists = self
            .conn
            .query_row(
                "SELECT 1 FROM seen_ids WHERE archive_key = ?1 AND record_id = ?2",
                params![&self.archive_key, record_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|e| format!("query seen id: {e}"))?;
        Ok(exists.is_some())
    }

    pub fn commit_backup_state(
        &mut self,
        checkpoint_updates: &[(String, u64)],
        new_ids: &[String],
    ) -> AppResult<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin state transaction: {e}"))?;
        for (path, offset) in checkpoint_updates {
            tx.execute(
                "INSERT INTO checkpoints(archive_key, path, offset) VALUES(?1, ?2, ?3)
                 ON CONFLICT(archive_key, path) DO UPDATE SET offset = excluded.offset",
                params![
                    &self.archive_key,
                    path,
                    u64_to_i64(*offset, "checkpoint offset")?
                ],
            )
            .map_err(|e| format!("write checkpoint: {e}"))?;
        }
        for id in new_ids {
            tx.execute(
                "INSERT OR IGNORE INTO seen_ids(archive_key, record_id) VALUES(?1, ?2)",
                params![&self.archive_key, id],
            )
            .map_err(|e| format!("write seen id: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("commit state transaction: {e}"))
    }

    pub fn reset_for_init(&mut self) -> AppResult<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin state reset: {e}"))?;
        tx.execute(
            "DELETE FROM checkpoints WHERE archive_key = ?1",
            params![&self.archive_key],
        )
        .map_err(|e| format!("reset checkpoints: {e}"))?;
        tx.execute(
            "DELETE FROM seen_ids WHERE archive_key = ?1",
            params![&self.archive_key],
        )
        .map_err(|e| format!("reset seen ids: {e}"))?;
        tx.execute(
            "INSERT OR REPLACE INTO state_meta(archive_key, key, value) VALUES(?1, ?2, '1')",
            params![&self.archive_key, LEGACY_TSV_MIGRATION_KEY],
        )
        .map_err(|e| format!("write legacy migration marker: {e}"))?;
        tx.commit().map_err(|e| format!("commit state reset: {e}"))
    }

    fn init_schema(&self) -> AppResult<()> {
        self.conn
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS state_meta (
                     archive_key TEXT NOT NULL,
                     key TEXT NOT NULL,
                     value TEXT NOT NULL,
                     PRIMARY KEY(archive_key, key)
                 );
                 CREATE TABLE IF NOT EXISTS checkpoints (
                     archive_key TEXT NOT NULL,
                     path TEXT NOT NULL,
                     offset INTEGER NOT NULL CHECK(offset >= 0),
                     PRIMARY KEY(archive_key, path)
                 );
                 CREATE TABLE IF NOT EXISTS seen_ids (
                     archive_key TEXT NOT NULL,
                     record_id TEXT NOT NULL,
                     PRIMARY KEY(archive_key, record_id)
                 );",
            )
            .map_err(|e| format!("initialize state db schema: {e}"))
    }

    fn migrate_legacy_tsv(&mut self, root: &Path) -> AppResult<()> {
        let migrated = self
            .conn
            .query_row(
                "SELECT value FROM state_meta WHERE archive_key = ?1 AND key = ?2",
                params![&self.archive_key, LEGACY_TSV_MIGRATION_KEY],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| format!("query legacy migration marker: {e}"))?;
        if migrated.as_deref() == Some("1") {
            return Ok(());
        }

        let checkpoint_rows = read_legacy_checkpoints(&root.join("state").join("checkpoints.tsv"))?;
        let seen_ids = read_legacy_seen_ids(&root.join("state").join("seen_ids.txt"))?;
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin legacy migration: {e}"))?;
        for (path, offset) in checkpoint_rows {
            tx.execute(
                "INSERT OR IGNORE INTO checkpoints(archive_key, path, offset) VALUES(?1, ?2, ?3)",
                params![
                    &self.archive_key,
                    path,
                    u64_to_i64(offset, "legacy checkpoint offset")?
                ],
            )
            .map_err(|e| format!("migrate checkpoint: {e}"))?;
        }
        for id in seen_ids {
            tx.execute(
                "INSERT OR IGNORE INTO seen_ids(archive_key, record_id) VALUES(?1, ?2)",
                params![&self.archive_key, id],
            )
            .map_err(|e| format!("migrate seen id: {e}"))?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO state_meta(archive_key, key, value) VALUES(?1, ?2, '1')",
            params![&self.archive_key, LEGACY_TSV_MIGRATION_KEY],
        )
        .map_err(|e| format!("write legacy migration marker: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit legacy migration: {e}"))
    }
}

fn read_legacy_checkpoints(path: &Path) -> AppResult<Vec<(String, u64)>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut rows = Vec::new();
    for line in
        BufReader::new(File::open(path).map_err(|e| format!("open checkpoints: {e}"))?).lines()
    {
        let line = line.map_err(|e| format!("read checkpoints: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, '\t').collect();
        if parts.len() != 2 {
            continue;
        }
        if let Ok(offset) = parts[1].parse::<u64>() {
            rows.push((parts[0].to_string(), offset));
        }
    }
    Ok(rows)
}

fn read_legacy_seen_ids(path: &Path) -> AppResult<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for line in BufReader::new(File::open(path).map_err(|e| format!("open seen_ids: {e}"))?).lines()
    {
        let line = line.map_err(|e| format!("read seen_ids: {e}"))?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            ids.push(trimmed.to_string());
        }
    }
    Ok(ids)
}

fn u64_to_i64(value: u64, label: &str) -> AppResult<i64> {
    i64::try_from(value).map_err(|_| format!("{label} out of range for sqlite integer: {value}"))
}

fn i64_to_u64(value: i64) -> AppResult<u64> {
    u64::try_from(value).map_err(|_| format!("negative checkpoint offset in state db: {value}"))
}

pub fn load_manifest_entries(root: &Path) -> AppResult<Vec<ManifestEntry>> {
    let path = root.join("manifests").join("manifest.tsv");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let f = File::open(path).map_err(|e| format!("open manifest: {e}"))?;
    let mut out = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line.map_err(|e| format!("read manifest: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let p: Vec<&str> = line.splitn(8, '\t').collect();
        if p.len() != 8 {
            return Err("invalid manifest line field count".to_string());
        }
        let record_count = p[5]
            .parse::<usize>()
            .map_err(|e| format!("invalid manifest record_count: {e}"))?;
        out.push(ManifestEntry {
            manifest_hash: p[0].to_string(),
            prev_hash: p[1].to_string(),
            created_at: p[2].to_string(),
            chunk_id: p[3].to_string(),
            chunk_rel: p[4].to_string(),
            record_count,
            plain_sha: p[6].to_string(),
            cipher_sha: p[7].to_string(),
        });
    }
    Ok(out)
}

pub fn load_env_file(path: &Path) -> AppResult<HashMap<String, String>> {
    let f = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut map = HashMap::new();
    for line in BufReader::new(f).lines() {
        let line = line.map_err(|e| format!("read {}: {e}", path.display()))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut split = trimmed.splitn(2, '=');
        let k = split.next().unwrap_or("").trim();
        let v = split.next().unwrap_or("").trim();
        if !k.is_empty() {
            map.insert(k.to_string(), v.to_string());
        }
    }
    Ok(map)
}

pub fn sync_to_remote(root: &Path, remote: &Path, chunk_file: Option<&Path>) -> AppResult<()> {
    fs::create_dir_all(remote).map_err(|e| format!("mkdir remote: {e}"))?;

    let chunk_dir = remote.join("chunks");
    fs::create_dir_all(&chunk_dir).map_err(|e| format!("mkdir remote/chunks: {e}"))?;
    copy_dir_files(&root.join("chunks"), &chunk_dir, "chunks")?;
    if let Some(chunk) = chunk_file
        && !chunk.starts_with(root.join("chunks"))
    {
        copy_file_to_dir(chunk, &chunk_dir, "chunk")?;
    }

    for rel in ["manifests", "keys"] {
        let src_dir = root.join(rel);
        let dst_dir = remote.join(rel);
        fs::create_dir_all(&dst_dir).map_err(|e| format!("mkdir remote/{rel}: {e}"))?;
        copy_dir_files(&src_dir, &dst_dir, rel)?;
    }
    let config_src = root.join("config.json");
    if config_src.exists() {
        fs::copy(&config_src, remote.join("config.json"))
            .map_err(|e| format!("copy config: {e}"))?;
    }
    Ok(())
}

fn copy_dir_files(src_dir: &Path, dst_dir: &Path, label: &str) -> AppResult<()> {
    if !src_dir.exists() {
        return Ok(());
    }
    for entry in
        fs::read_dir(src_dir).map_err(|e| format!("read_dir {}: {e}", src_dir.display()))?
    {
        let entry = entry.map_err(|e| format!("read_dir entry {}: {e}", src_dir.display()))?;
        let path = entry.path();
        if path.is_file() {
            copy_file_to_dir(&path, dst_dir, label)?;
        }
    }
    Ok(())
}

fn copy_file_to_dir(path: &Path, dst_dir: &Path, label: &str) -> AppResult<()> {
    let target = dst_dir.join(
        path.file_name()
            .ok_or_else(|| format!("invalid {label} filename {}", path.display()))?,
    );
    fs::copy(path, &target)
        .map_err(|e| format!("copy {} -> {}: {e}", path.display(), target.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::error::Error;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn state_store_migrates_legacy_tsv_files() -> Result<(), Box<dyn Error>> {
        let root = test_dir("state-migrates-legacy")?;
        let archive = root.join("archive");
        fs::create_dir_all(archive.join("state"))?;
        fs::write(
            archive.join("state").join("checkpoints.tsv"),
            "/tmp/source.jsonl\t42\ninvalid\n/tmp/bad\tnope\n",
        )?;
        fs::write(
            archive.join("state").join("seen_ids.txt"),
            "abc123\n\nxyz789\n",
        )?;

        let store = StateStore::open(&archive)?;

        assert_eq!(store.checkpoint("/tmp/source.jsonl")?, Some(42));
        assert_eq!(store.checkpoint("/tmp/bad")?, None);
        assert!(store.has_seen_id("abc123")?);
        assert!(store.has_seen_id("xyz789")?);
        assert!(!store.has_seen_id("missing")?);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn sync_to_remote_repairs_missing_older_chunks() -> Result<(), Box<dyn Error>> {
        let root = test_dir("sync-repairs-chunks")?;
        let archive = root.join("archive");
        let remote = root.join("remote");
        fs::create_dir_all(archive.join("chunks"))?;
        fs::create_dir_all(archive.join("manifests"))?;
        fs::create_dir_all(archive.join("keys"))?;

        let old_chunk = archive.join("chunks").join("old.enc");
        let new_chunk = archive.join("chunks").join("new.enc");
        fs::write(&old_chunk, b"old")?;
        fs::write(&new_chunk, b"new")?;
        fs::write(archive.join("manifests").join("manifest.tsv"), b"manifest")?;
        fs::write(archive.join("keys").join("keys.env"), b"keys")?;

        fs::create_dir_all(remote.join("manifests"))?;
        fs::write(
            remote.join("manifests").join("manifest.tsv"),
            b"stale manifest",
        )?;

        sync_to_remote(&archive, &remote, Some(&new_chunk))?;

        assert_eq!(fs::read(remote.join("chunks").join("old.enc"))?, b"old");
        assert_eq!(fs::read(remote.join("chunks").join("new.enc"))?, b"new");
        assert_eq!(
            fs::read(remote.join("manifests").join("manifest.tsv"))?,
            b"manifest"
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn test_dir(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!(
            "chat-archive-rs-{tag}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}
