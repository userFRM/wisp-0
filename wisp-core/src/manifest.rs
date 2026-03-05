use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Result, WispError};
use crate::types::Digest32;
use crate::varint;

/// A single entry in a directory manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Relative path (Unix-style forward slashes).
    pub path: String,
    /// File size in bytes.
    pub size: u64,
    /// SHA-256 digest of the file's recipe wire encoding.
    pub recipe_digest: Digest32,
}

/// An ordered list of files describing a directory tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub entries: Vec<ManifestEntry>,
}

/// Conflict resolution policy for bidirectional sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictPolicy {
    /// Initiator's version wins — conflicts go from initiator to responder.
    InitiatorWins,
    /// Responder's version wins — conflicts go from responder to initiator.
    ResponderWins,
    /// Skip conflicting files — neither side overwrites.
    Skip,
}

/// Result of comparing two manifests.
#[derive(Debug, Clone)]
pub struct ManifestDiff {
    /// Files present in `other` but not in `self`.
    pub added: Vec<ManifestEntry>,
    /// Paths present in `self` but not in `other`.
    pub removed: Vec<String>,
    /// Files present in both but with different recipe_digest.
    pub changed: Vec<(ManifestEntry, ManifestEntry)>,
    /// Files identical in both manifests.
    pub unchanged: Vec<ManifestEntry>,
}

impl Manifest {
    /// Encode to wire format.
    ///
    /// Layout:
    ///   varint num_entries
    ///   repeat num_entries:
    ///     varint  path_len
    ///     bytes   path (UTF-8)
    ///     u64_le  size
    ///     bytes32 recipe_digest
    pub fn encode_wire(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        varint::encode_vec(self.entries.len() as u64, &mut buf);
        for entry in &self.entries {
            let path_bytes = entry.path.as_bytes();
            varint::encode_vec(path_bytes.len() as u64, &mut buf);
            buf.extend_from_slice(path_bytes);
            buf.extend_from_slice(&entry.size.to_le_bytes());
            buf.extend_from_slice(&entry.recipe_digest.0);
        }
        buf
    }

    /// Decode from wire format.
    pub fn decode_wire(data: &[u8]) -> Result<Self> {
        let (num_entries, mut off) = varint::decode(data, 0)?;
        let num_entries = num_entries as usize;

        // Cap allocation to prevent OOM from malicious input.
        let remaining = data.len().saturating_sub(off);
        let min_entry_size = 1 + 8 + 32; // at least 1 byte path + size + digest
        let max_entries = remaining / min_entry_size;
        let cap = num_entries.min(max_entries);

        let mut entries = Vec::with_capacity(cap);
        for _ in 0..num_entries {
            let (path_len, new_off) = varint::decode(data, off)?;
            off = new_off;
            let path_len = path_len as usize;
            if off + path_len > data.len() {
                return Err(WispError::BufferUnderflow);
            }
            let path = core::str::from_utf8(&data[off..off + path_len])
                .map_err(|_| WispError::InvalidData)?;
            off += path_len;

            if off + 8 + 32 > data.len() {
                return Err(WispError::BufferUnderflow);
            }
            let size = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            off += 8;
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&data[off..off + 32]);
            off += 32;

            entries.push(ManifestEntry {
                path: String::from(path),
                size,
                recipe_digest: Digest32(digest),
            });
        }
        Ok(Self { entries })
    }

    /// Compare this manifest against `other`. Returns what changed from self → other.
    pub fn diff(&self, other: &Manifest) -> ManifestDiff {
        use hashbrown::HashMap;

        let self_map: HashMap<&str, &ManifestEntry> =
            self.entries.iter().map(|e| (e.path.as_str(), e)).collect();
        let other_map: HashMap<&str, &ManifestEntry> =
            other.entries.iter().map(|e| (e.path.as_str(), e)).collect();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        let mut unchanged = Vec::new();

        // Files in other but not in self → added.
        // Files in both → check digest.
        for entry in &other.entries {
            match self_map.get(entry.path.as_str()) {
                None => added.push(entry.clone()),
                Some(self_entry) => {
                    if self_entry.recipe_digest != entry.recipe_digest {
                        changed.push(((*self_entry).clone(), entry.clone()));
                    } else {
                        unchanged.push(entry.clone());
                    }
                }
            }
        }

        // Files in self but not in other → removed.
        for entry in &self.entries {
            if !other_map.contains_key(entry.path.as_str()) {
                removed.push(entry.path.clone());
            }
        }

        ManifestDiff {
            added,
            removed,
            changed,
            unchanged,
        }
    }
}

/// Encode a list of file paths to wire format (for MANIFEST_ACK).
///
/// Layout:
///   varint num_paths
///   repeat:
///     varint path_len
///     bytes  path (UTF-8)
pub fn encode_paths_wire(paths: &[&str]) -> Vec<u8> {
    let mut buf = Vec::new();
    varint::encode_vec(paths.len() as u64, &mut buf);
    for path in paths {
        let bytes = path.as_bytes();
        varint::encode_vec(bytes.len() as u64, &mut buf);
        buf.extend_from_slice(bytes);
    }
    buf
}

/// Decode a list of file paths from wire format.
pub fn decode_paths_wire(data: &[u8]) -> Result<Vec<String>> {
    let (num_paths, mut off) = varint::decode(data, 0)?;
    let num_paths = num_paths as usize;

    let remaining = data.len().saturating_sub(off);
    let cap = num_paths.min(remaining);
    let mut paths = Vec::with_capacity(cap);

    for _ in 0..num_paths {
        let (path_len, new_off) = varint::decode(data, off)?;
        off = new_off;
        let path_len = path_len as usize;
        if off + path_len > data.len() {
            return Err(WispError::BufferUnderflow);
        }
        let path = core::str::from_utf8(&data[off..off + path_len])
            .map_err(|_| WispError::InvalidData)?;
        off += path_len;
        paths.push(String::from(path));
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(path: &str, size: u64, fill: u8) -> ManifestEntry {
        ManifestEntry {
            path: String::from(path),
            size,
            recipe_digest: Digest32([fill; 32]),
        }
    }

    #[test]
    fn round_trip_empty() {
        let m = Manifest { entries: vec![] };
        let wire = m.encode_wire();
        let decoded = Manifest::decode_wire(&wire).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn round_trip_single() {
        let m = Manifest {
            entries: vec![make_entry("src/main.rs", 1234, 0xAA)],
        };
        let wire = m.encode_wire();
        let decoded = Manifest::decode_wire(&wire).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn round_trip_multiple() {
        let m = Manifest {
            entries: vec![
                make_entry("a.txt", 100, 0x11),
                make_entry("b/c.txt", 200, 0x22),
                make_entry("d/e/f.bin", 999999, 0x33),
            ],
        };
        let wire = m.encode_wire();
        let decoded = Manifest::decode_wire(&wire).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn diff_all_new() {
        let old = Manifest { entries: vec![] };
        let new = Manifest {
            entries: vec![make_entry("a.txt", 100, 0x11)],
        };
        let d = old.diff(&new);
        assert_eq!(d.added.len(), 1);
        assert!(d.removed.is_empty());
        assert!(d.changed.is_empty());
        assert!(d.unchanged.is_empty());
    }

    #[test]
    fn diff_removed() {
        let old = Manifest {
            entries: vec![make_entry("a.txt", 100, 0x11)],
        };
        let new = Manifest { entries: vec![] };
        let d = old.diff(&new);
        assert!(d.added.is_empty());
        assert_eq!(d.removed, vec!["a.txt"]);
        assert!(d.changed.is_empty());
        assert!(d.unchanged.is_empty());
    }

    #[test]
    fn diff_changed() {
        let old = Manifest {
            entries: vec![make_entry("a.txt", 100, 0x11)],
        };
        let new = Manifest {
            entries: vec![make_entry("a.txt", 150, 0x22)],
        };
        let d = old.diff(&new);
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
        assert_eq!(d.changed.len(), 1);
        assert!(d.unchanged.is_empty());
    }

    #[test]
    fn diff_unchanged() {
        let old = Manifest {
            entries: vec![make_entry("a.txt", 100, 0x11)],
        };
        let new = Manifest {
            entries: vec![make_entry("a.txt", 100, 0x11)],
        };
        let d = old.diff(&new);
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
        assert!(d.changed.is_empty());
        assert_eq!(d.unchanged.len(), 1);
    }

    #[test]
    fn diff_mixed() {
        let old = Manifest {
            entries: vec![
                make_entry("keep.txt", 100, 0x11),
                make_entry("removed.txt", 200, 0x22),
                make_entry("changed.txt", 300, 0x33),
            ],
        };
        let new = Manifest {
            entries: vec![
                make_entry("keep.txt", 100, 0x11),
                make_entry("changed.txt", 400, 0x44),
                make_entry("added.txt", 500, 0x55),
            ],
        };
        let d = old.diff(&new);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].path, "added.txt");
        assert_eq!(d.removed, vec!["removed.txt"]);
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].0.path, "changed.txt");
        assert_eq!(d.unchanged.len(), 1);
        assert_eq!(d.unchanged[0].path, "keep.txt");
    }

    #[test]
    fn paths_wire_round_trip() {
        let paths = vec!["a.txt", "b/c.rs", "d/e/f.bin"];
        let wire = encode_paths_wire(&paths);
        let decoded = decode_paths_wire(&wire).unwrap();
        assert_eq!(decoded, paths);
    }

    #[test]
    fn paths_wire_empty() {
        let paths: Vec<&str> = vec![];
        let wire = encode_paths_wire(&paths);
        let decoded = decode_paths_wire(&wire).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn truncated_manifest_errors() {
        let err = Manifest::decode_wire(&[0x01]).unwrap_err();
        assert!(matches!(err, WispError::BufferUnderflow));
    }
}
