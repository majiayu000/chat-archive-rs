use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};

use crate::crypto::sha256_bytes;
use crate::types::{AppResult, ManifestEntry};
use crate::utils::{random_hex, resolve_archive_path};

const LEGACY_TSV_MIGRATION_KEY: &str = "legacy_tsv_migrated";
const DEFAULT_DB_FILE: &str = concat!("state", ".db");

pub fn ensure_layout(root: &Path) -> AppResult<()> {
    for rel in ["chunks", "manifests", "state", "keys", "tmp", "remote_sync"] {
        fs::create_dir_all(root.join(rel)).map_err(|e| format!("create dir {rel}: {e}"))?;
    }
    Ok(())
}

pub fn lock_archive_publication(root: &Path) -> AppResult<File> {
    fs::create_dir_all(root.join("state")).map_err(|e| format!("create state dir: {e}"))?;
    // Keep this file in place: deleting a locked file would let another writer
    // lock a different inode. Closing the handle also releases it after a kill.
    let lock_path = root.join("state/init.lock");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = match options.open(&lock_path) {
        Ok(lock) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Restore owner access only for this newly created inode;
                // existing locks keep their permissions and contents.
                lock.set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("chmod init lock: {e}"))?;
            }
            lock
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .map_err(|e| format!("open init lock: {e}"))?,
        Err(err) => return Err(format!("open init lock: {err}")),
    };
    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => {
            Err("archive initialization already in progress".to_string())
        }
        Err(TryLockError::Error(err)) => Err(format!("lock init: {err}")),
    }
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

    #[cfg(test)]
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

    pub fn recover_pending_backups(&mut self, root: &Path) -> AppResult<usize> {
        let op_ids = self.pending_backup_op_ids()?;
        let mut recovered = 0usize;
        for op_id in op_ids {
            let manifest_entries = self.pending_manifest_entries(&op_id)?;
            if manifest_entries.is_empty() {
                self.discard_pending_backup(root, &op_id)?;
                continue;
            }

            if manifest_contains_pending_lines(root, &manifest_entries)? {
                for (chunk_rel, manifest_line) in &manifest_entries {
                    let cipher_sha = manifest_line
                        .splitn(8, '\t')
                        .nth(7)
                        .ok_or_else(|| "invalid pending manifest line field count".to_string())?;
                    let chunk_path = resolve_archive_path(root, chunk_rel)?;
                    // FlushFileBuffers requires write access on Windows.
                    let mut chunk = File::options()
                        .read(true)
                        .write(cfg!(windows))
                        .open(&chunk_path)
                        .map_err(|e| format!("open pending chunk {}: {e}", chunk_path.display()))?;
                    let mut cipher = Vec::new();
                    chunk
                        .read_to_end(&mut cipher)
                        .map_err(|e| format!("read pending chunk {}: {e}", chunk_path.display()))?;
                    if sha256_bytes(&cipher)? != cipher_sha {
                        return Err(format!("Cipher hash mismatch: {}", chunk_path.display()));
                    }
                    chunk
                        .sync_all()
                        .map_err(|e| format!("sync pending chunk {}: {e}", chunk_path.display()))?;
                }
                sync_archive_metadata(root)?;
                self.commit_pending_backup_state(&op_id)?;
                recovered += 1;
            } else {
                self.discard_pending_backup(root, &op_id)?;
            }
        }
        Ok(recovered)
    }

    pub fn begin_pending_backup(&mut self, op_id: &str) -> AppResult<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin pending backup: {e}"))?;
        delete_pending_backup_rows(&tx, &self.archive_key, op_id)?;
        tx.execute(
            "INSERT INTO pending_backup_ops(archive_key, op_id) VALUES(?1, ?2)",
            params![&self.archive_key, op_id],
        )
        .map_err(|e| format!("create pending backup: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit pending backup begin: {e}"))
    }

    pub fn stage_pending_seen_id(&self, op_id: &str, record_id: &str) -> AppResult<bool> {
        let inserted = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO pending_backup_seen_ids(archive_key, op_id, record_id)
                 SELECT ?1, ?2, ?3
                 WHERE NOT EXISTS (
                     SELECT 1 FROM seen_ids WHERE archive_key = ?1 AND record_id = ?3
                 )",
                params![&self.archive_key, op_id, record_id],
            )
            .map_err(|e| format!("stage pending seen id: {e}"))?;
        Ok(inserted == 1)
    }

    pub fn stage_pending_checkpoint_updates(
        &mut self,
        op_id: &str,
        checkpoint_updates: &[(String, u64)],
    ) -> AppResult<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin pending checkpoints: {e}"))?;
        tx.execute(
            "DELETE FROM pending_backup_checkpoints WHERE archive_key = ?1 AND op_id = ?2",
            params![&self.archive_key, op_id],
        )
        .map_err(|e| format!("clear pending checkpoints: {e}"))?;
        for (path, offset) in checkpoint_updates {
            tx.execute(
                "INSERT INTO pending_backup_checkpoints(archive_key, op_id, path, offset)
                 VALUES(?1, ?2, ?3, ?4)",
                params![
                    &self.archive_key,
                    op_id,
                    path,
                    u64_to_i64(*offset, "pending checkpoint offset")?
                ],
            )
            .map_err(|e| format!("stage pending checkpoint: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("commit pending checkpoints: {e}"))
    }

    pub fn stage_pending_manifest_entries(
        &mut self,
        op_id: &str,
        entries: &[(String, String)],
    ) -> AppResult<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin pending manifest entries: {e}"))?;
        tx.execute(
            "DELETE FROM pending_backup_manifest_entries WHERE archive_key = ?1 AND op_id = ?2",
            params![&self.archive_key, op_id],
        )
        .map_err(|e| format!("clear pending manifest entries: {e}"))?;
        for (idx, (chunk_rel, manifest_line)) in entries.iter().enumerate() {
            tx.execute(
                "INSERT INTO pending_backup_manifest_entries(
                     archive_key, op_id, ordinal, chunk_rel, manifest_line
                 ) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    &self.archive_key,
                    op_id,
                    u64_to_i64(idx as u64, "pending manifest ordinal")?,
                    chunk_rel,
                    manifest_line
                ],
            )
            .map_err(|e| format!("stage pending manifest entry: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("commit pending manifest entries: {e}"))
    }

    pub fn commit_pending_backup_state(&mut self, op_id: &str) -> AppResult<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin pending state commit: {e}"))?;
        tx.execute(
            "INSERT OR REPLACE INTO checkpoints(archive_key, path, offset)
             SELECT archive_key, path, offset
             FROM pending_backup_checkpoints
             WHERE archive_key = ?1 AND op_id = ?2",
            params![&self.archive_key, op_id],
        )
        .map_err(|e| format!("commit pending checkpoints: {e}"))?;
        tx.execute(
            "INSERT OR IGNORE INTO seen_ids(archive_key, record_id)
             SELECT archive_key, record_id
             FROM pending_backup_seen_ids
             WHERE archive_key = ?1 AND op_id = ?2",
            params![&self.archive_key, op_id],
        )
        .map_err(|e| format!("commit pending seen ids: {e}"))?;
        delete_pending_backup_rows(&tx, &self.archive_key, op_id)?;
        tx.commit()
            .map_err(|e| format!("commit pending state transaction: {e}"))
    }

    pub fn discard_pending_backup(&mut self, root: &Path, op_id: &str) -> AppResult<()> {
        let manifest_lines = manifest_line_set(root)?;
        for (chunk_rel, manifest_line) in self.pending_manifest_entries(op_id)? {
            if manifest_lines.contains(&manifest_line) {
                continue;
            }
            let chunk_path = resolve_archive_path(root, &chunk_rel)?;
            if chunk_path.exists() {
                fs::remove_file(&chunk_path)
                    .map_err(|e| format!("remove abandoned chunk {}: {e}", chunk_path.display()))?;
            }
        }
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin pending discard: {e}"))?;
        delete_pending_backup_rows(&tx, &self.archive_key, op_id)?;
        tx.commit()
            .map_err(|e| format!("commit pending discard: {e}"))
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
            "DELETE FROM pending_backup_manifest_entries WHERE archive_key = ?1",
            params![&self.archive_key],
        )
        .map_err(|e| format!("reset pending manifest entries: {e}"))?;
        tx.execute(
            "DELETE FROM pending_backup_checkpoints WHERE archive_key = ?1",
            params![&self.archive_key],
        )
        .map_err(|e| format!("reset pending checkpoints: {e}"))?;
        tx.execute(
            "DELETE FROM pending_backup_seen_ids WHERE archive_key = ?1",
            params![&self.archive_key],
        )
        .map_err(|e| format!("reset pending seen ids: {e}"))?;
        tx.execute(
            "DELETE FROM pending_backup_ops WHERE archive_key = ?1",
            params![&self.archive_key],
        )
        .map_err(|e| format!("reset pending backup ops: {e}"))?;
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
	                 );
	                 CREATE TABLE IF NOT EXISTS pending_backup_ops (
	                     archive_key TEXT NOT NULL,
	                     op_id TEXT NOT NULL,
	                     PRIMARY KEY(archive_key, op_id)
	                 );
	                 CREATE TABLE IF NOT EXISTS pending_backup_checkpoints (
	                     archive_key TEXT NOT NULL,
	                     op_id TEXT NOT NULL,
	                     path TEXT NOT NULL,
	                     offset INTEGER NOT NULL CHECK(offset >= 0),
	                     PRIMARY KEY(archive_key, op_id, path)
	                 );
	                 CREATE TABLE IF NOT EXISTS pending_backup_seen_ids (
	                     archive_key TEXT NOT NULL,
	                     op_id TEXT NOT NULL,
	                     record_id TEXT NOT NULL,
	                     PRIMARY KEY(archive_key, op_id, record_id)
	                 );
	                 CREATE TABLE IF NOT EXISTS pending_backup_manifest_entries (
	                     archive_key TEXT NOT NULL,
	                     op_id TEXT NOT NULL,
	                     ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
	                     chunk_rel TEXT NOT NULL,
	                     manifest_line TEXT NOT NULL,
	                     PRIMARY KEY(archive_key, op_id, ordinal)
	                 );",
            )
            .map_err(|e| format!("initialize state db schema: {e}"))
    }

    fn pending_backup_op_ids(&self) -> AppResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT op_id FROM pending_backup_ops WHERE archive_key = ?1 ORDER BY op_id")
            .map_err(|e| format!("prepare pending backup ops: {e}"))?;
        let rows = stmt
            .query_map(params![&self.archive_key], |row| row.get::<_, String>(0))
            .map_err(|e| format!("query pending backup ops: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("read pending backup op: {e}"))
    }

    fn pending_manifest_entries(&self, op_id: &str) -> AppResult<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT chunk_rel, manifest_line
                 FROM pending_backup_manifest_entries
                 WHERE archive_key = ?1 AND op_id = ?2
                 ORDER BY ordinal",
            )
            .map_err(|e| format!("prepare pending manifest entries: {e}"))?;
        let rows = stmt
            .query_map(params![&self.archive_key, op_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| format!("query pending manifest entries: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("read pending manifest entry: {e}"))
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

fn delete_pending_backup_rows(
    tx: &rusqlite::Transaction<'_>,
    archive_key: &str,
    op_id: &str,
) -> AppResult<()> {
    for table in [
        "pending_backup_manifest_entries",
        "pending_backup_checkpoints",
        "pending_backup_seen_ids",
        "pending_backup_ops",
    ] {
        let sql = format!("DELETE FROM {table} WHERE archive_key = ?1 AND op_id = ?2");
        tx.execute(&sql, params![archive_key, op_id])
            .map_err(|e| format!("delete {table}: {e}"))?;
    }
    Ok(())
}

fn manifest_contains_pending_lines(root: &Path, entries: &[(String, String)]) -> AppResult<bool> {
    let manifest_lines = manifest_line_set(root)?;
    Ok(entries
        .iter()
        .all(|(_, manifest_line)| manifest_lines.contains(manifest_line)))
}

fn manifest_line_set(root: &Path) -> AppResult<HashSet<String>> {
    let path = root.join("manifests").join("manifest.tsv");
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let f = File::open(path).map_err(|e| format!("open manifest: {e}"))?;
    let mut lines = HashSet::new();
    for line in BufReader::new(f).lines() {
        let line = line.map_err(|e| format!("read manifest: {e}"))?;
        if !line.trim().is_empty() {
            lines.insert(line);
        }
    }
    Ok(lines)
}

pub fn sync_archive_metadata(root: &Path) -> AppResult<()> {
    // Windows flushes file metadata via FlushFileBuffers, using a writable
    // handle after rename. It does not support the Unix directory-sync path.
    // https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching
    let manifest_path = root.join("manifests/manifest.tsv");
    File::options()
        .read(true)
        .write(cfg!(windows))
        .open(&manifest_path)
        .and_then(|manifest| manifest.sync_all())
        .map_err(|e| format!("sync manifest {}: {e}", manifest_path.display()))?;

    #[cfg(not(windows))]
    for rel in ["chunks", "manifests"] {
        let path = root.join(rel);
        File::open(&path)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| format!("sync archive directory {}: {e}", path.display()))?;
    }
    Ok(())
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
    // Own the destination before copying any payload or either marker, using
    // the same process-held lock init takes before state/recovery-file effects.
    let _publication_lock = lock_archive_publication(remote)?;
    let remote = fs::canonicalize(remote).map_err(|e| format!("canonicalize remote: {e}"))?;

    let chunk_dir = remote_subdir(&remote, "chunks")?;
    copy_dir_files(&root.join("chunks"), &chunk_dir, "chunks")?;
    if let Some(chunk) = chunk_file
        && !chunk.starts_with(root.join("chunks"))
    {
        copy_file_to_dir(chunk, &chunk_dir, "chunk")?;
    }

    for rel in ["manifests", "keys"] {
        let src_dir = root.join(rel);
        let dst_dir = remote_subdir(&remote, rel)?;
        copy_dir_files(&src_dir, &dst_dir, rel)?;
    }
    let config_src = root.join("config.json");
    if config_src.exists() {
        copy_file_to_dir(&config_src, &remote, "config")
            .map_err(|e| format!("copy config: {e}"))?;
    }
    Ok(())
}

fn remote_subdir(remote: &Path, rel: &str) -> AppResult<PathBuf> {
    let dir = remote.join(rel);
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir remote/{rel}: {e}"))?;
    let dir = fs::canonicalize(&dir).map_err(|e| format!("canonicalize remote/{rel}: {e}"))?;
    if !dir.starts_with(remote) || dir == remote {
        return Err(format!("remote/{rel} escapes remote root"));
    }
    Ok(dir)
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
        if label == "keys" {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".keys.env.init-") && name.ends_with(".tmp") {
                continue;
            }
        }
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
    let copy_error = |e| format!("copy {} -> {}: {e}", path.display(), target.display());
    let mut source = File::open(path).map_err(copy_error)?;
    let permissions = source.metadata().map_err(copy_error)?.permissions();
    let stage = dst_dir.join(format!(".chat-archive-rs-sync-{}.tmp", random_hex(16)?));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut destination = options.open(&stage).map_err(copy_error)?;
    let result = (|| {
        std::io::copy(&mut source, &mut destination)?;
        destination.set_permissions(permissions)
    })();
    drop(destination);
    // Rename replaces the destination entry itself, including a dangling symlink.
    let result = result.and_then(|()| fs::rename(&stage, &target));
    if let Err(err) = result {
        let err = copy_error(err);
        return match fs::remove_file(&stage) {
            Ok(()) => Err(err),
            Err(cleanup) => Err(format!(
                "{err}; remove remote stage {}: {cleanup}",
                stage.display()
            )),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::error::Error;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    #[test]
    fn publication_lock_preserves_existing_file() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = test_dir("publication-existing-lock")?;
        ensure_layout(&root)?;
        let lock_path = root.join("state/init.lock");
        fs::write(&lock_path, b"existing lock contents")?;
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o640))?;
        let before = fs::metadata(&lock_path)?;
        let lock = lock_archive_publication(&root).map_err(std::io::Error::other)?;
        assert!(
            lock_archive_publication(&root)
                .expect_err("held lock allowed a competing writer")
                .contains("archive initialization already in progress")
        );
        drop(lock);
        let reopened = lock_archive_publication(&root).map_err(std::io::Error::other)?;
        assert_eq!(reopened.metadata()?.ino(), before.ino());
        assert_eq!(reopened.metadata()?.permissions().mode() & 0o777, 0o640);
        assert_eq!(fs::read(&lock_path)?, b"existing lock contents");
        drop(reopened);
        fs::remove_dir_all(root)?;
        Ok(())
    }

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
    fn sync_to_remote_refuses_locked_destination_without_copying() -> Result<(), Box<dyn Error>> {
        let root = test_dir("sync-init-ownership")?;
        let archive = root.join("archive");
        let remote = root.join("remote");
        ensure_layout(&archive)?;
        ensure_layout(&remote)?;
        let files = ["chunks/test.enc", "manifests/manifest.tsv", "keys/keys.env"];
        for file in files {
            fs::write(archive.join(file), b"incoming archive")?;
            fs::write(remote.join(file), b"destination archive")?;
        }
        let publication_lock = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(remote.join("state/init.lock"))?;
        publication_lock.lock()?;

        let result = sync_to_remote(&archive, &remote, None);
        assert!(
            result
                .expect_err("remote sync bypassed init ownership")
                .contains("archive initialization already in progress")
        );
        for file in files {
            assert_eq!(fs::read(remote.join(file))?, b"destination archive");
        }
        drop(publication_lock);
        sync_to_remote(&archive, &remote, None)?;
        for file in files {
            assert_eq!(fs::read(remote.join(file))?, b"incoming archive");
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn sync_to_remote_excludes_private_init_stages() -> Result<(), Box<dyn Error>> {
        let root = test_dir("sync-private-init-stages")?;
        let archive = root.join("archive");
        let remote = root.join("remote");
        ensure_layout(&archive)?;
        fs::write(archive.join("keys/keys.env"), b"published keys")?;
        fs::write(
            archive.join("keys/.keys.env.init-abandoned.tmp"),
            b"abandoned stage fixture",
        )?;
        fs::write(archive.join("keys/other.env"), b"other key file")?;
        sync_to_remote(&archive, &remote, None)?;
        assert!(!remote.join("keys/.keys.env.init-abandoned.tmp").exists());
        assert_eq!(fs::read(remote.join("keys/keys.env"))?, b"published keys");
        assert_eq!(fs::read(remote.join("keys/other.env"))?, b"other key file");
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

    #[test]
    #[cfg(unix)]
    fn sync_to_remote_replaces_destination_symlinks() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = test_dir("sync-file-symlinks")?;
        let archive = root.join("archive");
        let remote = root.join("remote");
        let outside = root.join("outside");
        fs::create_dir_all(&outside)?;
        for rel in [
            "chunks/old.enc",
            "manifests/manifest.tsv",
            "keys/keys.env",
            "config.json",
        ] {
            let source = archive.join(rel);
            let destination = remote.join(rel);
            fs::create_dir_all(source.parent().unwrap())?;
            fs::create_dir_all(destination.parent().unwrap())?;
            fs::write(&source, rel.as_bytes())?;
            fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
            let sentinel = outside.join(source.file_name().unwrap());
            fs::write(&sentinel, b"outside sentinel")?;
            symlink(&sentinel, &destination)?;
        }
        let extra_chunk = root.join("extra.enc");
        fs::write(&extra_chunk, b"extra chunk")?;
        symlink(outside.join("missing.enc"), remote.join("chunks/extra.enc"))?;

        sync_to_remote(&archive, &remote, Some(&extra_chunk))?;

        for rel in [
            "chunks/old.enc",
            "manifests/manifest.tsv",
            "keys/keys.env",
            "config.json",
        ] {
            let destination = remote.join(rel);
            assert_eq!(
                fs::read(outside.join(destination.file_name().unwrap()))?,
                b"outside sentinel",
                "{rel}"
            );
            assert!(
                !fs::symlink_metadata(&destination)?.file_type().is_symlink(),
                "{rel}"
            );
            assert_eq!(fs::read(&destination)?, rel.as_bytes());
            assert_eq!(
                fs::metadata(&destination)?.permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!outside.join("missing.enc").exists());
        assert_eq!(fs::read(remote.join("chunks/extra.enc"))?, b"extra chunk");
        assert!(
            !fs::symlink_metadata(remote.join("chunks/extra.enc"))?
                .file_type()
                .is_symlink()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn sync_to_remote_rejects_directory_symlink_escapes() -> Result<(), Box<dyn Error>> {
        let root = test_dir("sync-dir-symlinks")?;
        let archive = root.join("archive");
        for rel in ["chunks", "manifests", "keys"] {
            fs::create_dir_all(archive.join(rel))?;
            fs::write(archive.join(rel).join("sentinel"), b"archive bytes")?;
        }
        for rel in ["chunks", "manifests", "keys"] {
            let remote = root.join(format!("remote-{rel}"));
            let outside = root.join(format!("outside-{rel}"));
            fs::create_dir_all(&remote)?;
            fs::create_dir_all(&outside)?;
            fs::write(outside.join("sentinel"), b"outside sentinel")?;
            std::os::unix::fs::symlink(&outside, remote.join(rel))?;
            let result = sync_to_remote(&archive, &remote, None);
            assert_eq!(
                fs::read(outside.join("sentinel"))?,
                b"outside sentinel",
                "{rel}"
            );
            let err = result.expect_err("escaped destination must fail");
            assert!(err.contains("escapes remote root"), "{err}");
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn sync_to_remote_copy_error_preserves_destination() -> Result<(), Box<dyn Error>> {
        let root = test_dir("sync-copy-error")?;
        let archive = root.join("archive");
        let remote = root.join("remote");
        fs::create_dir_all(archive.join("keys"))?;
        fs::write(archive.join("keys/keys.env"), b"dummy key bytes")?;
        fs::create_dir_all(remote.join("keys/keys.env"))?;
        fs::write(remote.join("keys/keys.env/sentinel"), b"keep")?;

        let err = sync_to_remote(&archive, &remote, None).unwrap_err();
        assert!(err.starts_with("copy "), "{err}");
        assert!(err.contains("keys.env"), "{err}");
        assert_eq!(fs::read(remote.join("keys/keys.env/sentinel"))?, b"keep");
        assert_eq!(fs::read_dir(remote.join("keys"))?.count(), 1);

        fs::remove_dir_all(remote.join("keys/keys.env"))?;
        fs::write(archive.join("config.json"), b"dummy config")?;
        fs::create_dir(remote.join("config.json"))?;
        fs::write(remote.join("config.json/sentinel"), b"keep config")?;
        let err = sync_to_remote(&archive, &remote, None).unwrap_err();
        assert!(err.starts_with("copy config:"), "{err}");
        assert_eq!(
            fs::read(remote.join("config.json/sentinel"))?,
            b"keep config"
        );
        for entry in fs::read_dir(&remote)? {
            assert!(
                !entry?
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".chat-archive-rs-sync-"),
                "failed config publication left a temporary copy"
            );
        }

        let missing_chunk = root.join("missing.enc");
        let err = sync_to_remote(&archive, &remote, Some(&missing_chunk)).unwrap_err();
        assert!(err.starts_with("copy "), "{err}");
        assert!(err.contains("missing.enc"), "{err}");
        assert_eq!(fs::read_dir(remote.join("chunks"))?.count(), 0);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn discard_pending_backup_constrains_chunk_rel() {
        let root = test_dir("discard-chunk-rel").unwrap();
        let archive = root.join("archive");
        fs::create_dir_all(archive.join("chunks")).unwrap();
        fs::create_dir_all(archive.join("manifests")).unwrap();
        fs::write(archive.join("manifests").join("manifest.tsv"), b"").unwrap();
        let mut store = StateStore::open(&archive).unwrap();
        let outside = root.join("outside.enc");
        fs::write(&outside, b"secret").unwrap();

        stage_pending(&mut store, "escape", "../outside.enc");
        let err = store
            .discard_pending_backup(&archive, "escape")
            .unwrap_err();
        assert!(err.contains("'.' or '..'"), "{err}");
        assert_eq!(fs::read(&outside).unwrap(), b"secret");
        assert_eq!(store.pending_manifest_entries("escape").unwrap().len(), 1);

        let absolute = outside.to_str().unwrap();
        stage_pending(&mut store, "absolute", absolute);
        let err = store
            .discard_pending_backup(&archive, "absolute")
            .unwrap_err();
        assert!(err.contains("absolute"), "{err}");
        assert_eq!(fs::read(&outside).unwrap(), b"secret");
        assert_eq!(store.pending_manifest_entries("absolute").unwrap().len(), 1);

        #[cfg(unix)]
        {
            let outside_dir = root.join("outside");
            fs::create_dir(&outside_dir).unwrap();
            let secret = outside_dir.join("secret.enc");
            fs::write(&secret, b"secret").unwrap();
            std::os::unix::fs::symlink(&outside_dir, archive.join("linked-chunks")).unwrap();
            stage_pending(&mut store, "symlink", "linked-chunks/secret.enc");
            let err = store
                .discard_pending_backup(&archive, "symlink")
                .unwrap_err();
            assert!(err.contains("escapes"), "{err}");
            assert_eq!(fs::read(&secret).unwrap(), b"secret");
            assert_eq!(store.pending_manifest_entries("symlink").unwrap().len(), 1);
        }

        let abandoned = archive.join("chunks").join("abandoned.enc");
        fs::write(&abandoned, b"chunk").unwrap();
        stage_pending(&mut store, "abandon", "chunks/abandoned.enc");
        store.discard_pending_backup(&archive, "abandon").unwrap();
        assert!(!abandoned.exists());
        assert!(
            store
                .pending_manifest_entries("abandon")
                .unwrap()
                .is_empty()
        );

        stage_pending(&mut store, "missing", "chunks/missing.enc");
        store.discard_pending_backup(&archive, "missing").unwrap();
        assert!(!archive.join("chunks").join("missing.enc").exists());
        assert!(
            store
                .pending_manifest_entries("missing")
                .unwrap()
                .is_empty()
        );

        fs::remove_dir_all(root).unwrap();
    }

    fn stage_pending(store: &mut StateStore, op_id: &str, chunk_rel: &str) {
        store.begin_pending_backup(op_id).unwrap();
        store
            .stage_pending_manifest_entries(
                op_id,
                &[(chunk_rel.into(), format!("pending-{op_id}"))],
            )
            .unwrap();
    }

    #[test]
    fn pending_recovery_requires_all_chunks_before_committing_state() -> Result<(), Box<dyn Error>>
    {
        let root = test_dir("pending-recovery-chunks")?;
        let archive = root.join("archive");
        ensure_layout(&archive)?;
        let entries = [
            (
                "chunks/first.enc".to_string(),
                pending_manifest_line("chunks/first.enc", b"first cipher"),
            ),
            (
                "chunks/second.enc".to_string(),
                pending_manifest_line("chunks/second.enc", b"second cipher"),
            ),
        ];
        fs::write(archive.join("chunks/first.enc"), b"first cipher")?;
        fs::write(
            archive.join("manifests/manifest.tsv"),
            format!("{}\n{}\n", entries[0].1, entries[1].1),
        )?;
        let mut store = StateStore::open(&archive)?;
        store.begin_pending_backup("recover")?;
        store.stage_pending_seen_id("recover", "first-id")?;
        store.stage_pending_seen_id("recover", "second-id")?;
        store.stage_pending_checkpoint_updates("recover", &[("source.jsonl".into(), 42)])?;
        store.stage_pending_manifest_entries("recover", &entries)?;

        let err = store.recover_pending_backups(&archive).unwrap_err();
        assert!(err.contains("second.enc"), "{err}");
        assert!(!store.has_seen_id("first-id")?);
        assert!(!store.has_seen_id("second-id")?);
        assert_eq!(store.checkpoint("source.jsonl")?, None);
        assert_eq!(store.pending_manifest_entries("recover")?, entries);
        drop(store);

        let mut store = StateStore::open(&archive)?;
        fs::write(archive.join("chunks/second.enc"), b"corrupt cipher")?;
        let err = store.recover_pending_backups(&archive).unwrap_err();
        assert!(err.contains("Cipher hash mismatch"), "{err}");
        assert!(!store.has_seen_id("first-id")?);
        assert!(!store.has_seen_id("second-id")?);
        assert_eq!(store.checkpoint("source.jsonl")?, None);
        assert_eq!(store.pending_manifest_entries("recover")?, entries);

        fs::write(archive.join("chunks/second.enc"), b"second cipher")?;
        assert_eq!(store.recover_pending_backups(&archive)?, 1);
        assert!(store.has_seen_id("first-id")?);
        assert!(store.has_seen_id("second-id")?);
        assert_eq!(store.checkpoint("source.jsonl")?, Some(42));
        assert!(store.pending_backup_op_ids()?.is_empty());
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn pending_recovery_rejects_chunks_outside_archive() -> Result<(), Box<dyn Error>> {
        let root = test_dir("pending-recovery-paths")?;
        let archive = root.join("archive");
        ensure_layout(&archive)?;
        let outside = root.join("outside.enc");
        fs::write(&outside, b"cipher")?;
        let mut paths = vec![
            "../outside.enc".to_string(),
            outside.to_str().unwrap().into(),
        ];
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, archive.join("chunks/linked.enc"))?;
            paths.push("chunks/linked.enc".into());
        }

        let mut store = StateStore::open(&archive)?;
        for (idx, chunk_rel) in paths.iter().enumerate() {
            let op_id = format!("escape-{idx}");
            let line = pending_manifest_line(chunk_rel, b"cipher");
            fs::write(archive.join("manifests/manifest.tsv"), format!("{line}\n"))?;
            store.begin_pending_backup(&op_id)?;
            store.stage_pending_seen_id(&op_id, "must-not-skip")?;
            store.stage_pending_checkpoint_updates(&op_id, &[("source.jsonl".into(), 42)])?;
            store.stage_pending_manifest_entries(&op_id, &[(chunk_rel.clone(), line)])?;
            assert!(store.recover_pending_backups(&archive).is_err());
            assert!(!store.has_seen_id("must-not-skip")?);
            assert_eq!(store.checkpoint("source.jsonl")?, None);
            assert_eq!(store.pending_manifest_entries(&op_id)?.len(), 1);
            // Isolate each invalid path without discarding its chunk.
            let tx = store.conn.transaction()?;
            delete_pending_backup_rows(&tx, &store.archive_key, &op_id)?;
            tx.commit()?;
        }
        assert_eq!(fs::read(&outside)?, b"cipher");
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn pending_recovery_retains_state_when_files_cannot_be_synced() -> Result<(), Box<dyn Error>> {
        let root = test_dir("pending-recovery-readonly")?;
        let archive = root.join("archive");
        ensure_layout(&archive)?;
        let chunk_rel = "chunks/readonly.enc";
        let chunk_path = archive.join("chunks").join("readonly.enc");
        let manifest_path = archive.join("manifests/manifest.tsv");
        let entries = [(
            chunk_rel.to_string(),
            pending_manifest_line(chunk_rel, b"cipher"),
        )];
        fs::write(&chunk_path, b"cipher")?;
        fs::write(&manifest_path, format!("{}\n", entries[0].1))?;
        for path in [&chunk_path, &manifest_path] {
            // A read-only handle cannot call FlushFileBuffers on Windows,
            // even while the file itself is writable.
            let err = File::open(path)?.sync_all().unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
            File::options().write(true).open(path)?.sync_all()?;
        }
        let mut store = StateStore::open(&archive)?;
        store.begin_pending_backup("recover")?;
        store.stage_pending_seen_id("recover", "must-not-skip")?;
        store.stage_pending_checkpoint_updates("recover", &[("source.jsonl".into(), 42)])?;
        store.stage_pending_manifest_entries("recover", &entries)?;

        for (path, error_prefix) in [
            (&chunk_path, "open pending chunk "),
            (&manifest_path, "sync manifest "),
        ] {
            let original_permissions = fs::metadata(path)?.permissions();
            let mut readonly = original_permissions.clone();
            readonly.set_readonly(true);
            fs::set_permissions(path, readonly)?;
            let result = store.recover_pending_backups(&archive);
            fs::set_permissions(path, original_permissions)?;
            let err = result.unwrap_err();
            assert!(err.starts_with(error_prefix), "{err}");
            assert!(
                err.contains(path.file_name().unwrap().to_str().unwrap()),
                "{err}"
            );
            assert!(!store.has_seen_id("must-not-skip")?);
            assert_eq!(store.checkpoint("source.jsonl")?, None);
            assert_eq!(store.pending_manifest_entries("recover")?, entries);
            drop(store);
            store = StateStore::open(&archive)?;
        }

        assert_eq!(store.recover_pending_backups(&archive)?, 1);
        assert!(store.has_seen_id("must-not-skip")?);
        assert_eq!(store.checkpoint("source.jsonl")?, Some(42));
        assert!(store.pending_backup_op_ids()?.is_empty());
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn pending_manifest_line(chunk_rel: &str, cipher: &[u8]) -> String {
        let cipher_hash = crate::crypto::sha256_bytes(cipher).unwrap();
        let core =
            format!("-\t2026-09-30T00:00:00Z\tchunk-id\t{chunk_rel}\t1\tplain-sha\t{cipher_hash}");
        let manifest_hash = crate::crypto::sha256_bytes(core.as_bytes()).unwrap();
        format!("{manifest_hash}\t{core}")
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
