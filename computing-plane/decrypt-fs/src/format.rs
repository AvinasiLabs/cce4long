//! AVIN file format constants.
//!
//! Must stay in sync with `cced/src/encrypt/format.rs`.
//!
//! Layout:
//! ```text
//! Header: MAGIC(4B) + VERSION(1B) + CHUNK_COUNT(4B) = 9 bytes
//! Chunk:  IV(12B) + Ciphertext(≤4MB) + Tag(16B)
//! ```

pub const MAGIC: &[u8; 4] = b"AVIN";
pub const VERSION: u8 = 0x01;
pub const HEADER_SIZE: usize = 4 + 1 + 4; // magic + version + chunk_count
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MB
pub const IV_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
