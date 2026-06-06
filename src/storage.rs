use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::types::{AppResult, ManifestEntry};

pub fn ensure_layout(root: &Path) -> AppResult<()> {
    for rel in ["chunks", "manifests", "state", "keys", "tmp", "remote_sync"] {
        fs::create_dir_all(root.join(rel)).map_err(|e| format!("create dir {rel}: {e}"))?;
    }
    Ok(())
}

pub fn load_checkpoints(root: &Path) -> AppResult<HashMap<String, u64>> {
    let path = root.join("state").join("checkpoints.tsv");
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let mut map = HashMap::new();
    for line in
        BufReader::new(File::open(&path).map_err(|e| format!("open checkpoints: {e}"))?).lines()
    {
        let line = line.map_err(|e| format!("read checkpoints: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, '\t').collect();
        if parts.len() != 2 {
            continue;
        }
        if let Ok(v) = parts[1].parse::<u64>() {
            map.insert(parts[0].to_string(), v);
        }
    }
    Ok(map)
}

pub fn save_checkpoints(root: &Path, checkpoints: &HashMap<String, u64>) -> AppResult<()> {
    let mut pairs: Vec<_> = checkpoints.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let mut buf = Vec::new();
    for (k, v) in pairs {
        buf.extend_from_slice(format!("{k}\t{v}\n").as_bytes());
    }
    fs::write(root.join("state").join("checkpoints.tsv"), buf)
        .map_err(|e| format!("write checkpoints: {e}"))
}

pub fn load_seen_ids(root: &Path) -> AppResult<HashSet<String>> {
    let path = root.join("state").join("seen_ids.txt");
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let mut set = HashSet::new();
    for line in BufReader::new(File::open(path).map_err(|e| format!("open seen_ids: {e}"))?).lines()
    {
        let line = line.map_err(|e| format!("read seen_ids: {e}"))?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            set.insert(trimmed.to_string());
        }
    }
    Ok(set)
}

pub fn append_seen_ids(root: &Path, ids: &[String]) -> AppResult<()> {
    let path = root.join("state").join("seen_ids.txt");
    let mut f = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|e| format!("open seen_ids append: {e}"))?;
    for id in ids {
        f.write_all(format!("{id}\n").as_bytes())
            .map_err(|e| format!("append seen id: {e}"))?;
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
