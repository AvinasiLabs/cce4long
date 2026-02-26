use std::path::Path;

use key_manager::Key;

use crate::error::AgentError;

/// Encrypt all files in `output_dir` using the REK and AVIN format.
/// Returns the concatenated encrypted bytes (each file as a separate AVIN blob).
///
/// Output format: for each file, produces `{filename}.avin` in the same directory.
pub fn encrypt_output(rek: &Key, output_dir: &str) -> Result<Vec<EncryptedFile>, AgentError> {
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

        let encrypted = decrypt_fs::encrypt_avin(rek, &plaintext);

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
}
