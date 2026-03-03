use std::path::Path;

use sha2::{Digest, Sha256};
use tracing::debug;

use key_manager::Key;

use crate::error::AgentError;

/// Encrypt all files in `output_dir` using the REK and AVIN format.
/// Returns the concatenated encrypted bytes (each file as a separate AVIN blob).
///
/// Output format: for each file, produces `{filename}.avin` in the same directory.
pub fn encrypt_output(rek: &Key, output_dir: &str) -> Result<Vec<EncryptedFile>, AgentError> {
    debug!(output_dir, "encrypting output files");
    let dir = Path::new(output_dir);
    let entries = std::fs::read_dir(dir)
        .map_err(|e| AgentError::Config(format!("cannot read output dir {output_dir}: {e}")))?;

    let mut results = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|e| AgentError::Config(format!("read dir entry failed: {e}")))?;
        let path = entry.path();

        // Skip directories and already-encrypted files
        if !path.is_file() || path.extension().is_some_and(|ext| ext == "avin") {
            continue;
        }

        let plaintext = std::fs::read(&path)
            .map_err(|e| AgentError::Config(format!("cannot read {}: {e}", path.display())))?;

        let encrypted = decrypt_fs::encrypt_avin(rek, &plaintext)
            .map_err(|e| AgentError::Config(format!("encrypt {}: {e}", path.display())))?;

        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        results.push(EncryptedFile {
            filename,
            data: encrypted,
        });
    }

    Ok(results)
}

/// An encrypted output file.
#[derive(Debug)]
pub struct EncryptedFile {
    pub filename: String,
    pub data: Vec<u8>,
}

/// Compute a deterministic hash over encrypted files.
/// Sort by filename, then SHA256(concat all encrypted data).
pub fn compute_result_hash(files: &[EncryptedFile]) -> [u8; 32] {
    let mut sorted: Vec<&EncryptedFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.filename.cmp(&b.filename));

    let mut hasher = Sha256::new();
    for f in &sorted {
        hasher.update(f.filename.as_bytes());
        hasher.update(&f.data);
    }
    hasher.finalize().into()
}

/// Write encrypted files to disk as {filename}.avin.
pub fn write_encrypted_files(
    files: &[EncryptedFile],
    output_dir: &str,
) -> Result<(), AgentError> {
    let dir = Path::new(output_dir);
    for f in files {
        let path = dir.join(format!("{}.avin", f.filename));
        std::fs::write(&path, &f.data)
            .map_err(|e| AgentError::Config(format!("write {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_key() -> Key {
        Key([0x42; 32])
    }

    #[test]
    fn encrypt_output_files() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("result.csv"), "col1,col2\n1,2").unwrap();
        fs::write(tmp.path().join("model.bin"), vec![0xAA; 100]).unwrap();

        let rek = test_key();
        let files = encrypt_output(&rek, tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(files.len(), 2);

        // Each encrypted file should be decryptable
        for ef in &files {
            let decrypted = decrypt_fs::decrypt_avin(&rek, &ef.data).unwrap();
            let original =
                fs::read(tmp.path().join(&ef.filename)).unwrap();
            assert_eq!(decrypted, original);
        }
    }

    #[test]
    fn encrypt_output_skips_avin_files() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("data.csv"), "test").unwrap();
        fs::write(tmp.path().join("already.avin"), "encrypted").unwrap();

        let files = encrypt_output(&test_key(), tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "data.csv");
    }

    #[test]
    fn encrypt_output_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let files = encrypt_output(&test_key(), tmp.path().to_str().unwrap()).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn encrypted_output_decryptable_with_rek() {
        let tmp = tempfile::tempdir().unwrap();
        let content = b"important computation result";
        fs::write(tmp.path().join("output.txt"), content).unwrap();

        let rek = test_key();
        let files = encrypt_output(&rek, tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(files.len(), 1);

        let decrypted = decrypt_fs::decrypt_avin(&rek, &files[0].data).unwrap();
        assert_eq!(decrypted, content);
    }

    #[test]
    fn result_hash_includes_filename() {
        let data = vec![0xAA; 32];
        let files_a = vec![
            EncryptedFile { filename: "alpha.csv".into(), data: data.clone() },
        ];
        let files_b = vec![
            EncryptedFile { filename: "beta.csv".into(), data: data.clone() },
        ];
        assert_ne!(compute_result_hash(&files_a), compute_result_hash(&files_b));
    }

    #[test]
    fn result_hash_order_independent() {
        let f1 = EncryptedFile { filename: "a.csv".into(), data: vec![0x11; 16] };
        let f2 = EncryptedFile { filename: "b.csv".into(), data: vec![0x22; 16] };
        let hash_ab = compute_result_hash(&[f1, f2]);

        let f1 = EncryptedFile { filename: "a.csv".into(), data: vec![0x11; 16] };
        let f2 = EncryptedFile { filename: "b.csv".into(), data: vec![0x22; 16] };
        let hash_ba = compute_result_hash(&[f2, f1]);

        assert_eq!(hash_ab, hash_ba);
    }

    // --- T1: write_encrypted_files tests ---

    #[test]
    fn write_encrypted_files_creates_avin_files() {
        let tmp = tempfile::tempdir().unwrap();
        let files = vec![
            EncryptedFile { filename: "out1.csv".into(), data: vec![0xAA; 32] },
            EncryptedFile { filename: "out2.bin".into(), data: vec![0xBB; 16] },
        ];
        write_encrypted_files(&files, tmp.path().to_str().unwrap()).unwrap();

        let written1 = fs::read(tmp.path().join("out1.csv.avin")).unwrap();
        assert_eq!(written1, vec![0xAA; 32]);

        let written2 = fs::read(tmp.path().join("out2.bin.avin")).unwrap();
        assert_eq!(written2, vec![0xBB; 16]);
    }

    #[test]
    fn write_encrypted_files_empty_list_ok() {
        let tmp = tempfile::tempdir().unwrap();
        write_encrypted_files(&[], tmp.path().to_str().unwrap()).unwrap();
        // No files created
        let entries: Vec<_> = fs::read_dir(tmp.path()).unwrap().collect();
        assert!(entries.is_empty());
    }

    #[test]
    fn write_encrypted_files_missing_dir_errors() {
        let files = vec![
            EncryptedFile { filename: "a.csv".into(), data: vec![1, 2, 3] },
        ];
        let err = write_encrypted_files(&files, "/nonexistent/path/xyz").unwrap_err();
        assert!(err.to_string().contains("write"));
    }

    // --- T2: result hash boundary tests ---

    #[test]
    fn result_hash_empty_files() {
        use sha2::{Digest, Sha256};
        let hash = compute_result_hash(&[]);
        let expected: [u8; 32] = Sha256::new().finalize().into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn result_hash_single_file_deterministic() {
        let f = || EncryptedFile { filename: "data.csv".into(), data: vec![0x42; 64] };
        let h1 = compute_result_hash(&[f()]);
        let h2 = compute_result_hash(&[f()]);
        assert_eq!(h1, h2);
    }
}
