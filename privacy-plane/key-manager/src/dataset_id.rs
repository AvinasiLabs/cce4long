use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Ethereum address as dataset identifier (20 bytes).
///
/// Represents a deterministic contract address (CREATE2) used as a
/// globally unique dataset ID across the entire protocol.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DatasetId([u8; 20]);

impl DatasetId {
    pub const ZERO: DatasetId = DatasetId([0u8; 20]);
}

impl fmt::Display for DatasetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl FromStr for DatasetId {
    type Err = DatasetIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_str = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        let bytes = hex::decode(hex_str).map_err(|e| DatasetIdError::InvalidHex(e.to_string()))?;
        if bytes.len() != 20 {
            return Err(DatasetIdError::InvalidLength(bytes.len()));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(DatasetId(arr))
    }
}

impl AsRef<[u8; 20]> for DatasetId {
    fn as_ref(&self) -> &[u8; 20] {
        &self.0
    }
}

impl From<[u8; 20]> for DatasetId {
    fn from(bytes: [u8; 20]) -> Self {
        DatasetId(bytes)
    }
}

impl From<DatasetId> for [u8; 20] {
    fn from(id: DatasetId) -> [u8; 20] {
        id.0
    }
}

impl Serialize for DatasetId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DatasetId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        DatasetId::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone)]
pub enum DatasetIdError {
    InvalidHex(String),
    InvalidLength(usize),
}

impl fmt::Display for DatasetIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatasetIdError::InvalidHex(e) => write!(f, "invalid hex: {}", e),
            DatasetIdError::InvalidLength(len) => {
                write!(f, "expected 20 bytes, got {}", len)
            }
        }
    }
}

impl std::error::Error for DatasetIdError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_format() {
        let id = DatasetId([0x1a; 20]);
        assert_eq!(
            id.to_string(),
            "0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
        );
    }

    #[test]
    fn from_str_with_prefix() {
        let id: DatasetId = "0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
            .parse()
            .unwrap();
        assert_eq!(id.0, [0x1a; 20]);
    }

    #[test]
    fn from_str_without_prefix() {
        let id: DatasetId = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
            .parse()
            .unwrap();
        assert_eq!(id.0, [0x1a; 20]);
    }

    #[test]
    fn from_str_uppercase_prefix() {
        let id: DatasetId = "0X1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
            .parse()
            .unwrap();
        assert_eq!(id.0, [0x1a; 20]);
    }

    #[test]
    fn from_str_invalid_hex() {
        assert!("0xZZZZ".parse::<DatasetId>().is_err());
    }

    #[test]
    fn from_str_wrong_length() {
        assert!("0x1a1a".parse::<DatasetId>().is_err());
    }

    #[test]
    fn roundtrip_display_from_str() {
        let id = DatasetId([0xab; 20]);
        let s = id.to_string();
        let parsed: DatasetId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn serde_json_roundtrip() {
        let id = DatasetId([0xcd; 20]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\"");
        let parsed: DatasetId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn as_ref_bytes() {
        let id = DatasetId([0x42; 20]);
        let bytes: &[u8; 20] = id.as_ref();
        assert_eq!(bytes, &[0x42; 20]);
    }

    #[test]
    fn from_into_bytes() {
        let bytes = [0xff; 20];
        let id = DatasetId::from(bytes);
        let back: [u8; 20] = id.into();
        assert_eq!(bytes, back);
    }
}
