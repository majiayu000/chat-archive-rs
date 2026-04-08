use std::collections::HashMap;
use std::path::PathBuf;

pub type AppResult<T> = Result<T, String>;

#[derive(Debug, Clone)]
pub struct Cli {
    pub archive_dir: PathBuf,
    pub command: String,
    pub options: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub provider: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub manifest_hash: String,
    pub prev_hash: String,
    pub created_at: String,
    pub chunk_id: String,
    pub chunk_rel: String,
    pub record_count: usize,
    pub plain_sha: String,
    pub cipher_sha: String,
}
