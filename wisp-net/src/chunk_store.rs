use std::collections::HashMap;
use wisp_core::types::ChunkId;

/// In-memory store for chunk data keyed by ChunkId.
pub struct ChunkStore {
    chunks: HashMap<ChunkId, Vec<u8>>,
}

impl ChunkStore {
    pub fn new() -> Self {
        Self {
            chunks: HashMap::new(),
        }
    }

    pub fn insert(&mut self, id: ChunkId, data: Vec<u8>) {
        self.chunks.insert(id, data);
    }

    pub fn get(&self, id: &ChunkId) -> Option<&[u8]> {
        self.chunks.get(id).map(|v| v.as_slice())
    }

    pub fn has(&self, id: &ChunkId) -> bool {
        self.chunks.contains_key(id)
    }

    pub fn keys(&self) -> impl Iterator<Item = &ChunkId> {
        self.chunks.keys()
    }
}

impl Default for ChunkStore {
    fn default() -> Self {
        Self::new()
    }
}
