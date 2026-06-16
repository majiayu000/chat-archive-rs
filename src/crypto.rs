use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::types::AppResult;
use crate::utils::hex_encode;

const WRAP_VERSION: u8 = 1;
const CHUNK_RAW_VERSION: u8 = 1;
const CHUNK_ZSTD_VERSION: u8 = 2;
const KDF_ITERS: u32 = 600_000;

pub fn sha256_bytes(bytes: &[u8]) -> AppResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    Ok(hex_encode(&out))
}

pub fn openssl_wrap_b64(plain: &[u8], pass: &str) -> AppResult<String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(pass, &salt);
    let cipher = encrypt_aes_gcm(plain, &key, &nonce)?;

    let mut blob = Vec::with_capacity(1 + 16 + 12 + cipher.len());
    blob.push(WRAP_VERSION);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&cipher);
    Ok(STANDARD_NO_PAD.encode(blob))
}

pub fn openssl_unwrap_b64(wrapped_b64: &str, pass: &str) -> AppResult<Vec<u8>> {
    let blob = STANDARD_NO_PAD
        .decode(wrapped_b64)
        .map_err(|e| format!("base64 decode wrapped key failed: {e}"))?;
    if blob.len() < 1 + 16 + 12 {
        return Err("wrapped key blob too short".to_string());
    }
    if blob[0] != WRAP_VERSION {
        return Err(format!("unsupported wrapped key version: {}", blob[0]));
    }
    let salt: [u8; 16] = blob[1..17]
        .try_into()
        .map_err(|_| "invalid wrapped key salt length".to_string())?;
    let nonce: [u8; 12] = blob[17..29]
        .try_into()
        .map_err(|_| "invalid wrapped key nonce length".to_string())?;
    let cipher = &blob[29..];
    let key = derive_key(pass, &salt);
    decrypt_aes_gcm(cipher, &key, &nonce)
}

#[cfg(test)]
pub fn openssl_encrypt_chunk(plain: &[u8], pass: &str) -> AppResult<Vec<u8>> {
    encrypt_chunk_payload(CHUNK_RAW_VERSION, plain, pass)
}

pub fn openssl_encrypt_chunk_with_level(
    plain: &[u8],
    pass: &str,
    compress_level: i32,
) -> AppResult<Vec<u8>> {
    if !(1..=19).contains(&compress_level) {
        return Err("invalid compression level: must be between 1 and 19".to_string());
    }
    let compressed = zstd::stream::encode_all(plain, compress_level)
        .map_err(|e| format!("zstd compression failed: {e}"))?;
    encrypt_chunk_payload(CHUNK_ZSTD_VERSION, &compressed, pass)
}

pub fn openssl_decrypt_chunk(cipher: &[u8], pass: &str) -> AppResult<Vec<u8>> {
    let (version, decrypted) = decrypt_chunk_payload(cipher, pass)?;
    match version {
        CHUNK_RAW_VERSION => Ok(decrypted),
        CHUNK_ZSTD_VERSION => zstd::stream::decode_all(decrypted.as_slice())
            .map_err(|e| format!("zstd decompression failed: {e}")),
        _ => Err(format!("unsupported chunk version: {version}")),
    }
}

fn encrypt_chunk_payload(version: u8, plain: &[u8], pass: &str) -> AppResult<Vec<u8>> {
    let key = key_from_secret(pass.as_bytes());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = encrypt_aes_gcm(plain, &key, &nonce)?;
    let mut out = Vec::with_capacity(1 + 12 + cipher.len());
    out.push(version);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&cipher);
    Ok(out)
}

fn decrypt_chunk_payload(cipher: &[u8], pass: &str) -> AppResult<(u8, Vec<u8>)> {
    if cipher.len() < 1 + 12 {
        return Err("encrypted chunk too short".to_string());
    }
    let version = cipher[0];
    if !matches!(version, CHUNK_RAW_VERSION | CHUNK_ZSTD_VERSION) {
        return Err(format!("unsupported chunk version: {version}"));
    }
    let nonce: [u8; 12] = cipher[1..13]
        .try_into()
        .map_err(|_| "invalid chunk nonce".to_string())?;
    let body = &cipher[13..];
    let key = key_from_secret(pass.as_bytes());
    Ok((version, decrypt_aes_gcm(body, &key, &nonce)?))
}

fn derive_key(pass: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pass.as_bytes(), salt, KDF_ITERS, &mut out);
    out
}

fn key_from_secret(secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    let digest = hasher.finalize();
    digest.into()
}

fn encrypt_aes_gcm(plain: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> AppResult<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| "invalid aes key length".to_string())?;
    let n = Nonce::from_slice(nonce);
    cipher
        .encrypt(n, plain)
        .map_err(|_| "encryption failed".to_string())
}

fn decrypt_aes_gcm(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> AppResult<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| "invalid aes key length".to_string())?;
    let n = Nonce::from_slice(nonce);
    cipher
        .decrypt(n, ciphertext)
        .map_err(|_| "decryption failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let wrapped = openssl_wrap_b64(b"hello", "pass-123").expect("wrap");
        let plain = openssl_unwrap_b64(&wrapped, "pass-123").expect("unwrap");
        assert_eq!(plain, b"hello");
    }

    #[test]
    fn test_chunk_encrypt_decrypt_roundtrip() {
        let enc = openssl_encrypt_chunk(b"data-123", "k").expect("enc");
        let dec = openssl_decrypt_chunk(&enc, "k").expect("dec");
        assert_eq!(dec, b"data-123");
    }

    #[test]
    fn test_compressed_chunk_encrypt_decrypt_roundtrip() -> AppResult<()> {
        let plain = b"chat archive line\n".repeat(256);
        let enc = openssl_encrypt_chunk_with_level(&plain, "k", 12)?;
        assert_eq!(enc[0], CHUNK_ZSTD_VERSION);
        let dec = openssl_decrypt_chunk(&enc, "k")?;
        assert_eq!(dec, plain);
        Ok(())
    }

    #[test]
    fn test_compressed_chunk_rejects_invalid_level() {
        let err = match openssl_encrypt_chunk_with_level(b"data", "k", 20) {
            Ok(_) => panic!("invalid compression level unexpectedly succeeded"),
            Err(err) => err,
        };
        assert_eq!(err, "invalid compression level: must be between 1 and 19");
    }
}
