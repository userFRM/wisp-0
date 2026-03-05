use std::fs;
use std::io;
use std::path::PathBuf;

use wisp_core::types::{ChunkId, Digest32};

/// Persists decoded chunks to disk for resume-on-reconnect.
///
/// Chunks are stored as individual files named by hex ChunkId.
/// Metadata (h_target + recipe wire) is stored separately for validation.
pub struct ResumeState {
    state_dir: PathBuf,
}

impl ResumeState {
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { state_dir: dir })
    }

    /// Persist a verified chunk to disk.
    pub fn save_chunk(&self, id: &ChunkId, data: &[u8]) -> io::Result<()> {
        let path = self.chunk_path(id);
        fs::write(path, data)
    }

    /// Load all previously-persisted chunks from the state directory.
    pub fn load_chunks(&self) -> io::Result<Vec<(ChunkId, Vec<u8>)>> {
        let chunks_dir = self.state_dir.join("chunks");
        if !chunks_dir.exists() {
            return Ok(Vec::new());
        }

        let mut chunks = Vec::new();
        for entry in fs::read_dir(&chunks_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.len() != 32 {
                continue; // skip non-chunk files
            }
            if let Some(id) = hex_to_chunk_id(&name_str) {
                let data = fs::read(entry.path())?;
                chunks.push((id, data));
            }
        }
        Ok(chunks)
    }

    /// Save transfer metadata (h_target + recipe wire bytes).
    pub fn save_metadata(&self, h_target: &Digest32, recipe_wire: &[u8]) -> io::Result<()> {
        let meta_path = self.state_dir.join("metadata");
        let mut buf = Vec::with_capacity(32 + recipe_wire.len());
        buf.extend_from_slice(&h_target.0);
        buf.extend_from_slice(recipe_wire);
        fs::write(meta_path, buf)
    }

    /// Load transfer metadata. Returns None if no metadata file exists.
    pub fn load_metadata(&self) -> io::Result<Option<(Digest32, Vec<u8>)>> {
        let meta_path = self.state_dir.join("metadata");
        if !meta_path.exists() {
            return Ok(None);
        }
        let buf = fs::read(&meta_path)?;
        if buf.len() < 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "resume metadata too short",
            ));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&buf[..32]);
        let recipe_wire = buf[32..].to_vec();
        Ok(Some((Digest32(digest), recipe_wire)))
    }

    /// Remove the state directory after successful transfer.
    pub fn cleanup(&self) -> io::Result<()> {
        if self.state_dir.exists() {
            fs::remove_dir_all(&self.state_dir)?;
        }
        Ok(())
    }

    fn chunk_path(&self, id: &ChunkId) -> PathBuf {
        let chunks_dir = self.state_dir.join("chunks");
        let _ = fs::create_dir_all(&chunks_dir);
        chunks_dir.join(chunk_id_to_hex(id))
    }
}

fn chunk_id_to_hex(id: &ChunkId) -> String {
    id.0.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_chunk_id(hex: &str) -> Option<ChunkId> {
    if hex.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for i in 0..16 {
        id[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(ChunkId(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wisp_core::chunk_id::h128;

    #[test]
    fn save_load_chunk_round_trip() {
        let dir = std::env::temp_dir().join("wisp_resume_test_1");
        let _ = fs::remove_dir_all(&dir);
        let state = ResumeState::new(dir.clone()).unwrap();

        let data = b"hello world";
        let id = h128(data);
        state.save_chunk(&id, data).unwrap();

        let chunks = state.load_chunks().unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, id);
        assert_eq!(chunks[0].1, data);

        state.cleanup().unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn save_load_metadata_round_trip() {
        let dir = std::env::temp_dir().join("wisp_resume_test_2");
        let _ = fs::remove_dir_all(&dir);
        let state = ResumeState::new(dir.clone()).unwrap();

        let digest = Digest32([0xAB; 32]);
        let wire = vec![1, 2, 3, 4, 5];
        state.save_metadata(&digest, &wire).unwrap();

        let (d, w) = state.load_metadata().unwrap().unwrap();
        assert_eq!(d, digest);
        assert_eq!(w, wire);

        state.cleanup().unwrap();
    }

    #[test]
    fn load_empty_dir() {
        let dir = std::env::temp_dir().join("wisp_resume_test_3");
        let _ = fs::remove_dir_all(&dir);
        let state = ResumeState::new(dir.clone()).unwrap();

        let chunks = state.load_chunks().unwrap();
        assert!(chunks.is_empty());
        assert!(state.load_metadata().unwrap().is_none());

        state.cleanup().unwrap();
    }

    #[test]
    fn multiple_chunks() {
        let dir = std::env::temp_dir().join("wisp_resume_test_4");
        let _ = fs::remove_dir_all(&dir);
        let state = ResumeState::new(dir.clone()).unwrap();

        for i in 0u8..10 {
            let data = vec![i; 100];
            let id = h128(&data);
            state.save_chunk(&id, &data).unwrap();
        }

        let chunks = state.load_chunks().unwrap();
        assert_eq!(chunks.len(), 10);

        state.cleanup().unwrap();
    }

    #[test]
    fn hex_round_trip() {
        let id = ChunkId([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67,
                          0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98]);
        let hex = chunk_id_to_hex(&id);
        let back = hex_to_chunk_id(&hex).unwrap();
        assert_eq!(id, back);
    }
}
