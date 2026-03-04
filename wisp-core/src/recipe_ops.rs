use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::error::{Result, WispError};
use crate::recipe::Recipe;
use crate::types::{ChunkId, RecipeEntry};
use crate::varint;

const OP_END: u8 = 0x00;
const OP_COPY: u8 = 0x01;
const OP_LIT: u8 = 0x02;

/// A single operation in the RecipeOps/0 delta format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipeOp {
    End,
    Copy { base_index: u64, count: u64 },
    Lit { entries: Vec<RecipeEntry> },
}

/// Encode a sequence of RecipeOps to wire format.
pub fn encode_ops(ops: &[RecipeOp]) -> Vec<u8> {
    let mut buf = Vec::new();
    for op in ops {
        match op {
            RecipeOp::End => {
                buf.push(OP_END);
            }
            RecipeOp::Copy { base_index, count } => {
                buf.push(OP_COPY);
                varint::encode_vec(*base_index, &mut buf);
                varint::encode_vec(*count, &mut buf);
            }
            RecipeOp::Lit { entries } => {
                buf.push(OP_LIT);
                varint::encode_vec(entries.len() as u64, &mut buf);
                for entry in entries {
                    buf.extend_from_slice(&entry.chunk_id.0);
                    varint::encode_vec(entry.chunk_len, &mut buf);
                }
            }
        }
    }
    buf
}

/// Decode wire format bytes into a sequence of RecipeOps.
pub fn decode_ops(data: &[u8]) -> Result<Vec<RecipeOp>> {
    let mut ops = Vec::new();
    let mut off = 0;
    while off < data.len() {
        let opcode = data[off];
        off += 1;
        match opcode {
            OP_END => {
                ops.push(RecipeOp::End);
                break;
            }
            OP_COPY => {
                let (base_index, new_off) = varint::decode(data, off)?;
                off = new_off;
                let (count, new_off) = varint::decode(data, off)?;
                off = new_off;
                ops.push(RecipeOp::Copy { base_index, count });
            }
            OP_LIT => {
                let (count, new_off) = varint::decode(data, off)?;
                off = new_off;
                let mut entries = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    if off + 16 > data.len() {
                        return Err(WispError::BufferUnderflow);
                    }
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&data[off..off + 16]);
                    off += 16;
                    let (chunk_len, new_off) = varint::decode(data, off)?;
                    off = new_off;
                    entries.push(RecipeEntry {
                        chunk_id: ChunkId(id),
                        chunk_len,
                    });
                }
                ops.push(RecipeOp::Lit { entries });
            }
            _ => return Err(WispError::InvalidRecipeOpcode(opcode)),
        }
    }
    Ok(ops)
}

/// Compute a greedy delta from `base` to `target`, returning the encoded ops bytes.
pub fn diff(base: &Recipe, target: &Recipe) -> Vec<u8> {
    let ops = diff_ops(base, target);
    encode_ops(&ops)
}

/// Compute a greedy delta from `base` to `target` as a Vec of RecipeOps.
fn diff_ops(base: &Recipe, target: &Recipe) -> Vec<RecipeOp> {
    // Build index: chunk_id -> list of positions in base
    let mut base_index: HashMap<ChunkId, Vec<usize>> = HashMap::new();
    for (i, entry) in base.entries.iter().enumerate() {
        base_index.entry(entry.chunk_id).or_default().push(i);
    }

    let mut ops: Vec<RecipeOp> = Vec::new();

    // Track pending COPY or LIT
    let mut copy_start: Option<usize> = None; // base index where current COPY run starts
    let mut copy_next: usize = 0; // next expected base index to extend COPY
    let mut copy_count: usize = 0;
    let mut lit_buf: Vec<RecipeEntry> = Vec::new();

    let flush_lit = |lit_buf: &mut Vec<RecipeEntry>, ops: &mut Vec<RecipeOp>| {
        if !lit_buf.is_empty() {
            ops.push(RecipeOp::Lit {
                entries: core::mem::take(lit_buf),
            });
        }
    };

    let flush_copy =
        |copy_start: &mut Option<usize>, copy_count: &mut usize, ops: &mut Vec<RecipeOp>| {
            if let Some(start) = copy_start.take() {
                ops.push(RecipeOp::Copy {
                    base_index: start as u64,
                    count: *copy_count as u64,
                });
                *copy_count = 0;
            }
        };

    for target_entry in &target.entries {
        // Can we extend current COPY run?
        if copy_start.is_some() {
            if copy_next < base.entries.len()
                && base.entries[copy_next].chunk_id == target_entry.chunk_id
                && base.entries[copy_next].chunk_len == target_entry.chunk_len
            {
                copy_count += 1;
                copy_next += 1;
                continue;
            }
            // Can't extend; flush COPY
            flush_copy(&mut copy_start, &mut copy_count, &mut ops);
        }

        // Try to start a new COPY from base
        if let Some(positions) = base_index.get(&target_entry.chunk_id) {
            // Find a position that matches chunk_len
            let found = positions.iter().find(|&&pos| {
                base.entries[pos].chunk_len == target_entry.chunk_len
            });
            if let Some(&pos) = found {
                // Flush any pending LIT
                flush_lit(&mut lit_buf, &mut ops);
                copy_start = Some(pos);
                copy_count = 1;
                copy_next = pos + 1;
                continue;
            }
        }

        // Accumulate as LIT
        lit_buf.push(*target_entry);
    }

    // Flush remaining
    flush_copy(&mut copy_start, &mut copy_count, &mut ops);
    flush_lit(&mut lit_buf, &mut ops);

    ops.push(RecipeOp::End);
    ops
}

/// Apply encoded ops to a base recipe, producing the target recipe.
pub fn apply(base: &Recipe, ops_data: &[u8]) -> Result<Recipe> {
    let ops = decode_ops(ops_data)?;
    let mut entries = Vec::new();
    for op in &ops {
        match op {
            RecipeOp::End => break,
            RecipeOp::Copy { base_index, count } => {
                let start = *base_index as usize;
                let end = start + *count as usize;
                if end > base.entries.len() {
                    return Err(WispError::BufferUnderflow);
                }
                entries.extend_from_slice(&base.entries[start..end]);
            }
            RecipeOp::Lit { entries: lit } => {
                entries.extend_from_slice(lit);
            }
        }
    }
    Ok(Recipe { entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_id::h128;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    fn make_entry(label: &[u8], len: u64) -> RecipeEntry {
        RecipeEntry {
            chunk_id: h128(label),
            chunk_len: len,
        }
    }

    fn make_recipe(labels: &[(&[u8], u64)]) -> Recipe {
        Recipe {
            entries: labels.iter().map(|(l, s)| make_entry(l, *s)).collect(),
        }
    }

    #[test]
    fn identity_diff_produces_single_copy() {
        let recipe = make_recipe(&[(b"a", 100), (b"b", 200), (b"c", 300)]);
        let ops_data = diff(&recipe, &recipe);
        let ops = decode_ops(&ops_data).unwrap();
        // Should be a single COPY of the entire base, then END
        assert_eq!(ops.len(), 2);
        assert_eq!(
            ops[0],
            RecipeOp::Copy {
                base_index: 0,
                count: 3
            }
        );
        assert_eq!(ops[1], RecipeOp::End);
    }

    #[test]
    fn apply_identity_diff_yields_original() {
        let recipe = make_recipe(&[(b"a", 100), (b"b", 200), (b"c", 300)]);
        let ops_data = diff(&recipe, &recipe);
        let result = apply(&recipe, &ops_data).unwrap();
        assert_eq!(result, recipe);
    }

    #[test]
    fn diff_apply_round_trip() {
        let base = make_recipe(&[(b"a", 100), (b"b", 200), (b"c", 300)]);
        let target = make_recipe(&[(b"a", 100), (b"x", 999), (b"c", 300)]);
        let ops_data = diff(&base, &target);
        let result = apply(&base, &ops_data).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn empty_base_non_empty_target_all_lit() {
        let base = Recipe { entries: vec![] };
        let target = make_recipe(&[(b"a", 100), (b"b", 200)]);
        let ops_data = diff(&base, &target);
        let ops = decode_ops(&ops_data).unwrap();
        // Should be LIT with 2 entries, then END
        assert_eq!(ops.len(), 2);
        match &ops[0] {
            RecipeOp::Lit { entries } => assert_eq!(entries.len(), 2),
            other => panic!("expected Lit, got {other:?}"),
        }
        assert_eq!(ops[1], RecipeOp::End);

        let result = apply(&base, &ops_data).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn empty_base_empty_target() {
        let base = Recipe { entries: vec![] };
        let target = Recipe { entries: vec![] };
        let ops_data = diff(&base, &target);
        let ops = decode_ops(&ops_data).unwrap();
        // Just END
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], RecipeOp::End);

        let result = apply(&base, &ops_data).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn encode_decode_round_trip() {
        let ops = vec![
            RecipeOp::Copy {
                base_index: 0,
                count: 3,
            },
            RecipeOp::Lit {
                entries: vec![make_entry(b"new", 512)],
            },
            RecipeOp::Copy {
                base_index: 5,
                count: 2,
            },
            RecipeOp::End,
        ];
        let encoded = encode_ops(&ops);
        let decoded = decode_ops(&encoded).unwrap();
        assert_eq!(decoded, ops);
    }

    #[test]
    fn invalid_opcode_errors() {
        let data = [0xFF]; // invalid opcode
        let err = decode_ops(&data).unwrap_err();
        assert!(matches!(err, WispError::InvalidRecipeOpcode(0xFF)));
    }

    #[test]
    fn copy_out_of_bounds_errors() {
        let base = make_recipe(&[(b"a", 100)]);
        // Manually encode a COPY that goes past the end
        let ops = vec![
            RecipeOp::Copy {
                base_index: 0,
                count: 10,
            },
            RecipeOp::End,
        ];
        let data = encode_ops(&ops);
        assert!(apply(&base, &data).is_err());
    }

    #[test]
    fn complex_diff_apply() {
        // base:   [a, b, c, d, e]
        // target: [a, b, x, y, d, e, z]
        // Expected: COPY(0,2), LIT(x,y), COPY(3,2), LIT(z), END
        let base = make_recipe(&[
            (b"a", 100),
            (b"b", 200),
            (b"c", 300),
            (b"d", 400),
            (b"e", 500),
        ]);
        let target = make_recipe(&[
            (b"a", 100),
            (b"b", 200),
            (b"x", 999),
            (b"y", 888),
            (b"d", 400),
            (b"e", 500),
            (b"z", 777),
        ]);
        let ops_data = diff(&base, &target);
        let result = apply(&base, &ops_data).unwrap();
        assert_eq!(result, target);

        // Verify the op structure
        let ops = decode_ops(&ops_data).unwrap();
        assert_eq!(
            ops,
            vec![
                RecipeOp::Copy {
                    base_index: 0,
                    count: 2
                },
                RecipeOp::Lit {
                    entries: vec![make_entry(b"x", 999), make_entry(b"y", 888)]
                },
                RecipeOp::Copy {
                    base_index: 3,
                    count: 2
                },
                RecipeOp::Lit {
                    entries: vec![make_entry(b"z", 777)]
                },
                RecipeOp::End,
            ]
        );
    }

    #[test]
    fn prepend_entries() {
        // target has new entries at the start
        let base = make_recipe(&[(b"a", 100), (b"b", 200)]);
        let target = make_recipe(&[(b"x", 50), (b"a", 100), (b"b", 200)]);
        let ops_data = diff(&base, &target);
        let result = apply(&base, &ops_data).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn append_entries() {
        let base = make_recipe(&[(b"a", 100), (b"b", 200)]);
        let target = make_recipe(&[(b"a", 100), (b"b", 200), (b"x", 50)]);
        let ops_data = diff(&base, &target);
        let result = apply(&base, &ops_data).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn all_replaced() {
        let base = make_recipe(&[(b"a", 100), (b"b", 200)]);
        let target = make_recipe(&[(b"x", 300), (b"y", 400)]);
        let ops_data = diff(&base, &target);
        let ops = decode_ops(&ops_data).unwrap();
        // All LIT since nothing matches
        assert_eq!(ops.len(), 2);
        match &ops[0] {
            RecipeOp::Lit { entries } => assert_eq!(entries.len(), 2),
            other => panic!("expected Lit, got {other:?}"),
        }
        assert_eq!(ops[1], RecipeOp::End);

        let result = apply(&base, &ops_data).unwrap();
        assert_eq!(result, target);
    }
}
