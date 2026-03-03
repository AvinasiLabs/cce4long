use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

use key_manager::Key;

use crate::error::DecryptFsError;
use crate::format::*;

/// Decrypt an AVIN-formatted byte buffer into plaintext.
pub fn decrypt_avin(dek: &Key, data: &[u8]) -> Result<Vec<u8>, DecryptFsError> {
    if data.len() < HEADER_SIZE {
        return Err(DecryptFsError::InvalidFormat("too short for header".into()));
    }

    // Verify magic
    if &data[..4] != MAGIC {
        return Err(DecryptFsError::InvalidFormat(format!(
            "bad magic: expected AVIN, got {:?}",
            &data[..4]
        )));
    }

    // Verify version
    if data[4] != VERSION {
        return Err(DecryptFsError::InvalidFormat(format!(
            "unsupported version: {}",
            data[4]
        )));
    }

    let chunk_count = u32::from_be_bytes(data[5..9].try_into().unwrap());

    if chunk_count > MAX_CHUNKS {
        return Err(DecryptFsError::InvalidFormat(format!(
            "chunk count {chunk_count} exceeds maximum {MAX_CHUNKS}"
        )));
    }

    let chunk_count = chunk_count as usize;

    if chunk_count == 0 {
        return Ok(Vec::new());
    }

    let cipher =
        Aes256Gcm::new_from_slice(dek.as_bytes()).map_err(|_| DecryptFsError::DecryptionFailed)?;

    let mut plaintext = Vec::new();
    let mut pos = HEADER_SIZE;

    for _ in 0..chunk_count {
        // Read IV
        if pos + IV_SIZE > data.len() {
            return Err(DecryptFsError::InvalidFormat(
                "truncated: missing IV".into(),
            ));
        }
        let iv = &data[pos..pos + IV_SIZE];
        pos += IV_SIZE;

        // Determine ciphertext+tag length for this chunk.
        // All chunks except possibly the last have CHUNK_SIZE plaintext bytes,
        // meaning CHUNK_SIZE + TAG_SIZE bytes of ciphertext (aes-gcm appends tag).
        // The last chunk takes whatever remains.
        let is_possibly_last = pos + CHUNK_SIZE + TAG_SIZE >= data.len();
        let ct_len = if is_possibly_last {
            data.len() - pos
        } else {
            CHUNK_SIZE + TAG_SIZE
        };

        if ct_len < TAG_SIZE {
            return Err(DecryptFsError::InvalidFormat(
                "truncated: chunk too short for tag".into(),
            ));
        }

        let nonce = Nonce::from_slice(iv);
        let chunk_plaintext = cipher
            .decrypt(nonce, &data[pos..pos + ct_len])
            .map_err(|_| DecryptFsError::DecryptionFailed)?;
        plaintext.extend_from_slice(&chunk_plaintext);
        pos += ct_len;
    }

    Ok(plaintext)
}

/// Encrypt plaintext into AVIN format. Mirrors cced's `encrypt_chunked`.
pub fn encrypt_avin(dek: &Key, plaintext: &[u8]) -> Result<Vec<u8>, DecryptFsError> {
    let cipher = Aes256Gcm::new(dek.as_bytes().into());
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![]
    } else {
        plaintext.chunks(CHUNK_SIZE).collect()
    };
    let chunk_count = chunks.len() as u32;

    if chunk_count > MAX_CHUNKS {
        return Err(DecryptFsError::InvalidFormat(format!(
            "chunk count {chunk_count} exceeds maximum {MAX_CHUNKS}"
        )));
    }

    let mut output = Vec::with_capacity(
        HEADER_SIZE + chunks.iter().map(|c| IV_SIZE + c.len() + TAG_SIZE).sum::<usize>(),
    );

    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(&chunk_count.to_be_bytes());

    let mut rng = rand::thread_rng();
    for chunk in &chunks {
        let mut iv = [0u8; IV_SIZE];
        rng.fill_bytes(&mut iv);
        let nonce = Nonce::from_slice(&iv);
        let ciphertext = cipher
            .encrypt(nonce, *chunk)
            .map_err(|_| DecryptFsError::EncryptionFailed)?;
        output.extend_from_slice(&iv);
        output.extend_from_slice(&ciphertext);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Key {
        Key([0x42; 32])
    }

    #[test]
    fn roundtrip_single_chunk() {
        let key = test_key();
        let plaintext = b"hello world, this is a test of AVIN decryption";
        let encrypted = encrypt_avin(&key, plaintext).unwrap();
        let decrypted = decrypt_avin(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let key = test_key();
        let plaintext = vec![0xAB; CHUNK_SIZE * 2 + 500];
        let encrypted = encrypt_avin(&key, &plaintext).unwrap();
        let decrypted = decrypt_avin(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_empty() {
        let key = test_key();
        let encrypted = encrypt_avin(&key, b"").unwrap();
        let decrypted = decrypt_avin(&key, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn roundtrip_exact_chunk_boundary() {
        let key = test_key();
        let plaintext = vec![0xEF; CHUNK_SIZE];
        let encrypted = encrypt_avin(&key, &plaintext).unwrap();
        let decrypted = decrypt_avin(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn bad_magic_rejected() {
        let key = test_key();
        let mut data = encrypt_avin(&key, b"test").unwrap();
        data[0] = b'X'; // corrupt magic
        let err = decrypt_avin(&key, &data).unwrap_err();
        assert!(err.to_string().contains("bad magic"));
    }

    #[test]
    fn wrong_dek_fails() {
        let key1 = Key([0x11; 32]);
        let key2 = Key([0x22; 32]);
        let encrypted = encrypt_avin(&key1, b"secret data").unwrap();
        let err = decrypt_avin(&key2, &encrypted).unwrap_err();
        assert!(matches!(err, DecryptFsError::DecryptionFailed));
    }

    #[test]
    fn truncated_data_fails() {
        let key = test_key();
        let encrypted = encrypt_avin(&key, b"test").unwrap();
        // Truncate to just header
        let err = decrypt_avin(&key, &encrypted[..HEADER_SIZE]).unwrap_err();
        assert!(err.to_string().contains("missing IV"));
    }

    #[test]
    fn too_short_for_header() {
        let key = test_key();
        let err = decrypt_avin(&key, &[0u8; 4]).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn decrypt_rejects_excessive_chunk_count() {
        let key = test_key();
        let mut header = Vec::new();
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.extend_from_slice(&(MAX_CHUNKS + 1).to_be_bytes());
        let err = decrypt_avin(&key, &header).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }
}
