use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use thiserror::Error;

use key_manager::Key;

use super::format::*;

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("AES-GCM encryption failed")]
    CipherError,
}

/// Encrypt plaintext into AVIN chunked format.
///
/// Returns the complete AVIN file bytes:
/// Header(9B) + Chunk[]{IV(12B) + Ciphertext + Tag(16B)}
pub fn encrypt_chunked(dek: &Key, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
    let cipher = Aes256Gcm::new(dek.as_bytes().into());

    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![]
    } else {
        plaintext.chunks(CHUNK_SIZE).collect()
    };
    let chunk_count = chunks.len() as u32;

    // Pre-allocate output buffer
    let mut output = Vec::with_capacity(
        HEADER_SIZE + chunks.iter().map(|c| IV_SIZE + c.len() + TAG_SIZE).sum::<usize>(),
    );

    // Write header
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(&chunk_count.to_be_bytes());

    // Encrypt each chunk
    let mut rng = rand::thread_rng();
    for chunk in &chunks {
        let mut iv = [0u8; IV_SIZE];
        rng.fill_bytes(&mut iv);
        let nonce = Nonce::from_slice(&iv);

        let ciphertext = cipher.encrypt(nonce, *chunk).map_err(|_| EncryptError::CipherError)?;
        // aes-gcm appends the tag to ciphertext, so ciphertext = encrypted_data || tag

        output.extend_from_slice(&iv);
        output.extend_from_slice(&ciphertext);
    }

    Ok(output)
}

/// Decrypt AVIN chunked format back to plaintext. Used in tests.
#[cfg(test)]
pub fn decrypt_chunked(dek: &Key, data: &[u8]) -> Result<Vec<u8>, EncryptError> {
    use aes_gcm::aead::generic_array::GenericArray;

    if data.len() < HEADER_SIZE {
        return Err(EncryptError::CipherError);
    }

    // Verify header
    if &data[..4] != MAGIC {
        return Err(EncryptError::CipherError);
    }
    if data[4] != VERSION {
        return Err(EncryptError::CipherError);
    }
    let chunk_count = u32::from_be_bytes(data[5..9].try_into().unwrap()) as usize;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(dek.as_bytes()));

    let mut plaintext = Vec::new();
    let mut pos = HEADER_SIZE;

    for _ in 0..chunk_count {
        if pos + IV_SIZE > data.len() {
            return Err(EncryptError::CipherError);
        }
        let iv = &data[pos..pos + IV_SIZE];
        pos += IV_SIZE;

        // Find the end of this chunk's ciphertext+tag.
        // We know max plaintext per chunk is CHUNK_SIZE, so max ciphertext+tag is CHUNK_SIZE + TAG_SIZE.
        // But for the last chunk it could be smaller. We need to figure out chunk boundaries.
        // Since ciphertext = plaintext_len + TAG_SIZE, and we don't store plaintext_len explicitly,
        // we compute: remaining_chunks_after_this = chunk_count - (current_chunk_index + 1)
        // For simplicity, for intermediate chunks the ciphertext size is CHUNK_SIZE + TAG_SIZE.
        // For the last chunk, it's whatever remains.

        // Actually, let's just compute based on position:
        // We know total chunks. All but last have ciphertext size = CHUNK_SIZE + TAG_SIZE.
        // Last chunk: remaining bytes.
        let remaining_chunks_after = chunk_count - (plaintext.len() / CHUNK_SIZE + 1).min(chunk_count);
        let _ = remaining_chunks_after; // not needed with the approach below

        // Better approach: parse forward, knowing that all chunks except possibly the last
        // have CHUNK_SIZE bytes of plaintext, meaning CHUNK_SIZE + TAG_SIZE bytes of ciphertext.
        let is_possibly_last = pos + CHUNK_SIZE + TAG_SIZE >= data.len();
        let ct_len = if is_possibly_last {
            data.len() - pos
        } else {
            CHUNK_SIZE + TAG_SIZE
        };

        let nonce = Nonce::from_slice(iv);
        let chunk_plaintext = cipher
            .decrypt(nonce, &data[pos..pos + ct_len])
            .map_err(|_| EncryptError::CipherError)?;
        plaintext.extend_from_slice(&chunk_plaintext);
        pos += ct_len;
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_manager::Key;

    fn test_key() -> Key {
        Key([0x42; 32])
    }

    #[test]
    fn encrypt_empty_input() {
        let result = encrypt_chunked(&test_key(), b"").unwrap();
        // Header only: AVIN + 0x01 + 0x00000000
        assert_eq!(result.len(), HEADER_SIZE);
        assert_eq!(&result[..4], MAGIC);
        assert_eq!(result[4], VERSION);
        assert_eq!(&result[5..9], &0u32.to_be_bytes());
    }

    #[test]
    fn encrypt_single_chunk() {
        let data = b"hello world";
        let result = encrypt_chunked(&test_key(), data).unwrap();

        // Header check
        assert_eq!(&result[..4], MAGIC);
        assert_eq!(result[4], VERSION);
        assert_eq!(&result[5..9], &1u32.to_be_bytes());

        // Should have: header + IV + ciphertext(11 bytes) + tag(16 bytes)
        let expected_len = HEADER_SIZE + IV_SIZE + data.len() + TAG_SIZE;
        assert_eq!(result.len(), expected_len);
    }

    #[test]
    fn encrypt_multi_chunk() {
        // Create data that spans 3 chunks: 4MB + 4MB + 1 byte
        let data = vec![0xAB; CHUNK_SIZE * 2 + 1];
        let result = encrypt_chunked(&test_key(), &data).unwrap();

        // Check chunk count
        assert_eq!(&result[5..9], &3u32.to_be_bytes());
    }

    #[test]
    fn roundtrip_small() {
        let key = test_key();
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let encrypted = encrypt_chunked(&key, plaintext).unwrap();
        let decrypted = decrypt_chunked(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let key = test_key();
        let plaintext = vec![0xCD; CHUNK_SIZE * 2 + 500];
        let encrypted = encrypt_chunked(&key, &plaintext).unwrap();
        let decrypted = decrypt_chunked(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_exact_chunk_boundary() {
        let key = test_key();
        let plaintext = vec![0xEF; CHUNK_SIZE];
        let encrypted = encrypt_chunked(&key, &plaintext).unwrap();
        let decrypted = decrypt_chunked(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_encryptions_produce_different_output() {
        let key = test_key();
        let plaintext = b"same input";
        let e1 = encrypt_chunked(&key, plaintext).unwrap();
        let e2 = encrypt_chunked(&key, plaintext).unwrap();
        // IVs are random, so ciphertext should differ
        assert_ne!(e1, e2);
        // But both should decrypt to the same plaintext
        assert_eq!(
            decrypt_chunked(&key, &e1).unwrap(),
            decrypt_chunked(&key, &e2).unwrap()
        );
    }
}
