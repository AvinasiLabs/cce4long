use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{Key, KeyError};

/// Bundle returned by `wrap_keys` — contains everything CVM needs to unwrap.
pub struct WrappedKeyBundle {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub pp_pk: [u8; 32],
}

/// Wrap DEKs + REK for transport to CVM using ECDHE.
///
/// Protocol:
/// 1. PP generates ephemeral x25519 keypair
/// 2. shared_secret = x25519(pp_sk, cvm_eph_pk)
/// 3. wrapping_key = HKDF(shared_secret, salt=pp_pk, info="key-wrapping")
/// 4. plaintext = num_deks(u16 BE) || dek_0(32B) || ... || rek(32B)
/// 5. ciphertext = AES-256-GCM(wrapping_key, random_nonce, plaintext)
pub fn wrap_keys(
    deks: &[Key],
    rek: &Key,
    cvm_eph_pk: &[u8; 32],
) -> Result<WrappedKeyBundle, KeyError> {
    let cvm_pk = PublicKey::from(*cvm_eph_pk);

    // PP generates ephemeral keypair (EphemeralSecret: single-use by type system)
    let pp_secret = EphemeralSecret::random_from_rng(OsRng);
    let pp_pk = PublicKey::from(&pp_secret);

    let shared_secret = pp_secret.diffie_hellman(&cvm_pk);

    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), pp_pk.as_bytes())?;

    // Build plaintext: num_deks(u16 BE) || dek_0 || ... || rek
    let num_deks = deks.len() as u16;
    let mut plaintext = Vec::with_capacity(2 + deks.len() * 32 + 32);
    plaintext.extend_from_slice(&num_deks.to_be_bytes());
    for dek in deks {
        plaintext.extend_from_slice(&dek.0);
    }
    plaintext.extend_from_slice(&rek.0);

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|e| KeyError::WrapFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| KeyError::WrapFailed(e.to_string()))?;

    Ok(WrappedKeyBundle {
        ciphertext,
        nonce: nonce_bytes,
        pp_pk: pp_pk.to_bytes(),
    })
}

/// Unwrap DEKs + REK received from PP.
/// Uses StaticSecret (reusable) on the CVM side for testing.
pub fn unwrap_keys(
    bundle: &WrappedKeyBundle,
    cvm_secret: &StaticSecret,
) -> Result<(Vec<Key>, Key), KeyError> {
    let pp_pk = PublicKey::from(bundle.pp_pk);
    let shared_secret = cvm_secret.diffie_hellman(&pp_pk);

    let wrapping_key = derive_wrapping_key(shared_secret.as_bytes(), &bundle.pp_pk)?;

    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|e| KeyError::UnwrapFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&bundle.nonce);
    let plaintext = cipher
        .decrypt(nonce, bundle.ciphertext.as_ref())
        .map_err(|e| KeyError::UnwrapFailed(e.to_string()))?;

    // Parse: num_deks(u16 BE) || dek_0(32B) || ... || rek(32B)
    if plaintext.len() < 2 {
        return Err(KeyError::UnwrapFailed("plaintext too short".into()));
    }
    let num_deks = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    let expected_len = 2 + num_deks * 32 + 32;
    if plaintext.len() != expected_len {
        return Err(KeyError::UnwrapFailed(format!(
            "expected {} bytes, got {}",
            expected_len,
            plaintext.len()
        )));
    }

    let mut deks = Vec::with_capacity(num_deks);
    for i in 0..num_deks {
        let start = 2 + i * 32;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&plaintext[start..start + 32]);
        deks.push(Key(buf));
    }

    let rek_start = 2 + num_deks * 32;
    let mut rek_buf = [0u8; 32];
    rek_buf.copy_from_slice(&plaintext[rek_start..rek_start + 32]);

    Ok((deks, Key(rek_buf)))
}

fn derive_wrapping_key(shared_secret: &[u8], pp_pk: &[u8]) -> Result<[u8; 32], KeyError> {
    let hk = Hkdf::<Sha256>::new(Some(pp_pk), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"key-wrapping", &mut key)
        .map_err(|_| KeyError::DerivationFailed)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::PublicKey;

    fn make_test_key(val: u8) -> Key {
        Key([val; 32])
    }

    fn make_cvm_keypair() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    #[test]
    fn ecdhe_roundtrip_single_dek() {
        let (cvm_sk, cvm_pk) = make_cvm_keypair();
        let dek = make_test_key(0x11);
        let rek = make_test_key(0x22);

        let bundle = wrap_keys(&[dek.clone()], &rek, cvm_pk.as_bytes()).unwrap();
        let (deks, got_rek) = unwrap_keys(&bundle, &cvm_sk).unwrap();

        assert_eq!(deks.len(), 1);
        assert_eq!(deks[0].0, [0x11; 32]);
        assert_eq!(got_rek.0, [0x22; 32]);
    }

    #[test]
    fn ecdhe_roundtrip_multi_dek() {
        let (cvm_sk, cvm_pk) = make_cvm_keypair();
        let deks: Vec<Key> = (1..=5).map(|i| make_test_key(i)).collect();
        let rek = make_test_key(0xFF);

        let bundle = wrap_keys(&deks, &rek, cvm_pk.as_bytes()).unwrap();
        let (got_deks, got_rek) = unwrap_keys(&bundle, &cvm_sk).unwrap();

        assert_eq!(got_deks.len(), 5);
        for (i, k) in got_deks.iter().enumerate() {
            assert_eq!(k.0, [i as u8 + 1; 32]);
        }
        assert_eq!(got_rek.0, [0xFF; 32]);
    }

    #[test]
    fn ecdhe_roundtrip_zero_deks() {
        let (cvm_sk, cvm_pk) = make_cvm_keypair();
        let rek = make_test_key(0xAA);

        let bundle = wrap_keys(&[], &rek, cvm_pk.as_bytes()).unwrap();
        let (deks, got_rek) = unwrap_keys(&bundle, &cvm_sk).unwrap();

        assert_eq!(deks.len(), 0);
        assert_eq!(got_rek.0, [0xAA; 32]);
    }

    #[test]
    fn wrong_key_unwrap_fails() {
        let (_cvm_sk, cvm_pk) = make_cvm_keypair();
        let (wrong_sk, _wrong_pk) = make_cvm_keypair();
        let rek = make_test_key(0x33);

        let bundle = wrap_keys(&[make_test_key(0x11)], &rek, cvm_pk.as_bytes()).unwrap();
        let result = unwrap_keys(&bundle, &wrong_sk);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let (cvm_sk, cvm_pk) = make_cvm_keypair();
        let rek = make_test_key(0x44);

        let mut bundle = wrap_keys(&[make_test_key(0x11)], &rek, cvm_pk.as_bytes()).unwrap();
        // Flip a byte in ciphertext
        if let Some(byte) = bundle.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        let result = unwrap_keys(&bundle, &cvm_sk);
        assert!(result.is_err());
    }

    #[test]
    fn each_wrap_produces_different_ciphertext() {
        let (_cvm_sk, cvm_pk) = make_cvm_keypair();
        let dek = make_test_key(0x55);
        let rek = make_test_key(0x66);

        let b1 = wrap_keys(&[dek.clone()], &rek, cvm_pk.as_bytes()).unwrap();
        let b2 = wrap_keys(&[dek], &rek, cvm_pk.as_bytes()).unwrap();

        // Different ephemeral keys + different nonces → different ciphertext
        assert_ne!(b1.ciphertext, b2.ciphertext);
        assert_ne!(b1.pp_pk, b2.pp_pk);
    }
}
