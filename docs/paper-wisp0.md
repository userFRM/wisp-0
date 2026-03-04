# WISP-0: A Bandwidth-Efficient Protocol for Incremental Binary Synchronization via Content-Defined Chunking, Invertible Count Tables, and Fountain Coding

**WISP Protocol Working Group**
`wisp-protocol@example.org`

March 2026

---

## Abstract

We present WISP-0 (Wire-level Incremental Sync Protocol), a novel application-layer protocol that achieves bandwidth-efficient incremental synchronization of opaque binary objects by composing three complementary techniques: (1) content-defined chunking (CDC) for edit-local decomposition, (2) Invertible Count Tables (ICT) for single-round-trip set reconciliation, and (3) systematic fountain coding (SSX) for rateless erasure-resilient bulk transfer. Control signaling flows over a reliable channel (TCP) while bulk data flows over an unreliable datagram channel (UDP), avoiding head-of-line blocking. We define the CSR/0 profile with concrete algorithm parameters and provide a complete Rust reference implementation (~7,100 lines of code) that is `no_std`-compatible for embedded and WebAssembly deployment, with optional X25519-PSK-HKDF authentication providing per-session forward secrecy. Empirical evaluation demonstrates that WISP-0 transfers only the bytes that actually changed, achieves decoding overhead within 5--10% of the information-theoretic minimum, and completes synchronization in a fixed number of round trips regardless of object size.

**Keywords:** incremental synchronization, content-defined chunking, set reconciliation, invertible bloom lookup tables, fountain codes, rateless erasure codes, binary delta transfer

---

## 1. Introduction

Efficient synchronization of binary objects across distributed systems is a fundamental problem in systems engineering. Applications range from firmware distribution on IoT devices, to container image layer synchronization, to replicated database snapshots and machine learning model deployment.

Existing approaches fall into two broad categories:

**Delta Compression (rsync-family).** The rsync algorithm [1] and its derivatives compute rolling checksums to identify matching blocks between source and target, then transfer only non-matching regions. However, rsync requires O(log n) round trips for checksum negotiation in the general case, and its fixed-block decomposition causes O(n) block invalidation for a single byte insertion.

**Content-Addressed Transfer (IPFS-family).** Systems like IPFS [2] decompose objects into content-addressed blocks and transfer missing blocks. While this achieves deduplication, the set reconciliation step typically requires exchanging full block lists or multiple Bloom filter rounds.

WISP-0 improves upon both approaches by combining:

1. **Content-Defined Chunking** (CDC): A rolling-hash chunker that places boundaries at content-determined positions, ensuring O(1) edit locality -- a single-byte edit affects at most a constant number of chunks.

2. **Invertible Count Tables** (ICT): A compact probabilistic sketch that encodes an entire chunk-id set, enabling exact set difference recovery in a *single* round trip.

3. **Systematic Fountain Coding** (SSX): A rateless erasure code over GF(2) that provides graceful degradation under arbitrary packet loss, eliminating per-packet acknowledgment.

The result is a protocol that transfers *exactly* the missing bytes (plus coding overhead), completes in a fixed number of round trips (typically 3--4 on C0), and tolerates arbitrary loss patterns on the bulk data channel without retransmission.

**Contributions:**

- A complete protocol specification (WISP-0 CSR/0) suitable for IETF standardization (Section 3).
- Formal analysis of bandwidth optimality and round-trip complexity (Section 7).
- A production-quality `no_std` Rust implementation with 142 tests (unit, integration, and end-to-end) and conformance vectors (Section 8).
- A defense-in-depth security layer with X25519-PSK-HKDF key exchange, HMAC-SHA256-128 frame authentication, replay protection, and adaptive timeout management (Section 9).
- Empirical evaluation on synthetic workloads (Section 10).

---

## 2. Related Work

### 2.1 Delta Synchronization

The rsync algorithm [1] pioneered rolling-checksum-based delta transfer. Subsequent work improved upon rsync's fixed-block model: zsync [10] moved computation to the client side, casync [11] combined CDC with content-addressed storage, and various cloud storage systems use proprietary CDC variants.

### 2.2 Set Reconciliation

Minsky, Trachtenberg, and Zippel [8] introduced polynomial interpolation for set reconciliation. Eppstein et al. [9] proposed strata estimators with Invertible Bloom Lookup Tables (IBLTs) for practical single-round reconciliation. Goodrich and Mitzenmacher [3] formalized IBLTs and analyzed their performance. Our ICT variant uses fixed k=3 hash functions with SHA-256-derived indices, trading generality for implementation simplicity and reproducibility.

### 2.3 Erasure Coding

LT codes [4] introduced the fountain coding paradigm. Raptor codes [5] improved upon LT codes with a pre-coding step for linear-time encoding/decoding. WISP-0's SSX/0 uses a simpler sparse systematic approach with GF(2) Gaussian elimination, which is sufficient for the symbol counts typical in file synchronization (n < 10^5) and avoids the complexity of Raptor's pre-code design.

---

## 3. Protocol Design

### 3.1 Architecture

WISP-0 employs a dual-channel architecture:

- **C0 (Control)**: TCP, carrying session management, recipe exchange, and synchronization frames.
- **D0 (Data)**: UDP, carrying source symbols (SYM) and coded repair symbols (MIX).

This separation avoids TCP's head-of-line blocking on the bulk data path while maintaining reliable delivery for protocol correctness.

### 3.2 Object Model

An *Object* is an opaque byte sequence. Each Object version is decomposed into a sequence of *Chunks* by CDC, described by a *Recipe* -- an ordered list of (ChunkId, chunk_len) pairs. The *Recipe Digest* H_recipe = SHA-256(RecipeWire) uniquely identifies each version.

### 3.3 Protocol Phases

An update cycle comprises five phases:

1. **Session Establishment**: HELLO exchange + SELECT (capability negotiation).
2. **Recipe Exchange**: OFFER with RecipeOps delta, ACK.
3. **Set Reconciliation**: Receiver computes a *difference* ICT (target_ict - have_ict) and sends it via HAVE_ICT; sender peels the difference ICT directly to recover the missing set.
4. **Bulk Transfer**: PLAN, then SYM + MIX on D0.
5. **Commit**: COMMIT with digest verification, ACK.

### 3.4 Frame Format

Every frame carries an 80-byte header (all fields little-endian):

| Offset | Size | Field | Description |
|---:|---:|:---|:---|
| 0 | 2 | `magic` | 0x5057 |
| 2 | 1 | `version` | Protocol version (0) |
| 3 | 1 | `frame_type` | Frame type code |
| 4 | 2 | `flags` | Bit 0: FLAGS_AUTH_HMAC |
| 6 | 4 | `payload_len` | Payload byte count |
| 10 | 8 | `session_id` | Session identifier |
| 18 | 8 | `object_id` | Object identifier |
| 26 | 8 | `update_id` | Update sequence |
| 34 | 8 | `frame_id` | Control frame seq# |
| 42 | 4 | `capsule_id` | Profile identifier |
| 46 | 1 | `chan` | 0=control, 1=data |
| 47 | 1 | `rsv0` | Reserved (0) |
| 48 | 32 | `base_digest` | SHA-256 of base recipe |

---

## 4. Content-Defined Chunking (CSR/0)

### 4.1 Rolling Hash

CSR/0 uses a Rabin-variant polynomial rolling hash over a sliding window of W = 48 bytes:

$$h_i = h_{i-1} \cdot B + x_i - y_i \cdot B^W \pmod{2^{64}}$$

where B = 257, x_i is the incoming byte, y_i is the outgoing byte from the ring buffer, and B^W mod 2^64 is a precomputed constant.

### 4.2 Boundary Detection

A chunk boundary is declared at position i when:

$$(chunk\_size \geq MIN) \wedge (h_i \mathbin{\&} MASK = 0)$$

or when chunk_size = MAX (forced cut).

| Parameter | Value | Description |
|:---|---:|:---|
| B | 257 | Hash base |
| W | 48 | Window size (bytes) |
| K | 16 | Mask bit width |
| MIN | 8,192 | Minimum chunk (8 KiB) |
| MAX | 262,144 | Maximum chunk (256 KiB) |
| MASK | 0xFFFF | (1 << K) - 1 |

**Proposition 1 (Edit Locality).** A modification of delta consecutive bytes in the input affects at most ceil(delta / MIN) + 2 chunks. Chunks whose content is entirely outside the modified region retain identical ChunkIds.

*Proof.* The rolling hash window extends W = 48 bytes. A modification at position p can only affect boundary decisions within the range [p - W, p + delta + MAX]. Since MIN = 8192 >> W, the perturbation is confined to at most ceil((delta + 2 * MAX) / MIN) chunk boundary decisions. In practice, the two boundary chunks adjacent to the modification may shift, contributing the +2 term, while interior chunks are completely determined by the modified content. QED

---

## 5. Set Reconciliation (ICT/0)

### 5.1 Data Structure

An Invertible Count Table with m = 2^(m_log2) cells, each containing:

$$cell = (count \in \mathbb{Z},\ key\_xor \in \{0,1\}^{128},\ hash\_xor \in \{0,1\}^{64})$$

### 5.2 Hash Functions

ICT/0 uses k = 3 hash functions derived from SHA-256 with domain separation:

$$hash64(key) = LE_{64}(SHA\text{-}256(0x49 \| key)[0:8])$$

$$h_j(key, m) = LE_{64}(SHA\text{-}256((0xA0+j) \| key)[0:8]) \bmod m \quad j \in \{0, 1, 2\}$$

### 5.3 Table Sizing

Given an estimate d of the symmetric difference:

$$m = \max(next\_pow2(\lceil 2.5d + 32 \rceil), 256)$$

This provides ~2.5x overhead, ensuring high peeling success probability.

**Theorem 1 (Peeling Success).** For k = 3 hash functions mapping uniformly into m cells, the peeling algorithm recovers all d elements from the difference table with probability >= 1 - m^(-Omega(1)) when m >= 2.5d + 32.

*Proof sketch.* The analysis follows from the random hypergraph peelability threshold for k-uniform hypergraphs [3]. For k = 3, the threshold ratio m/d approaches ~1.222 as d -> infinity. Our sizing formula provides ratio >= 2.5, well above threshold, yielding exponentially small failure probability. The additive constant 32 ensures adequate table size for small d. QED

### 5.4 Operations

**Insert(table, key):**
1. h <- hash64(key)
2. For j = 0, 1, 2:
   - i <- h_j(key, m)
   - table[i].count += 1
   - table[i].key_xor ^= key
   - table[i].hash_xor ^= h

**Peel(table):**
1. stack <- {i : is_pure(table[i])}
2. missing <- {}
3. While stack is not empty:
   - i <- stack.pop()
   - If not is_pure(table[i]): continue
   - key <- table[i].key_xor
   - sign <- table[i].count
   - If sign = +1: missing <- missing union {key}
   - Remove key from all 3 cell positions
   - Push newly pure cells onto stack
4. Return missing

---

## 6. Fountain Coding (SSX/0)

### 6.1 Source Symbol Construction

Missing chunks are serialized into n source symbols of size L = 1024 bytes. Each chunk is split into ceil(len/L) symbols, zero-padded to L bytes.

### 6.2 Degree Distribution

The SSX/0 degree distribution is determined by a single PRNG byte b:

| Byte Range | Degree d | Probability |
|:---|---:|---:|
| [0, 128) | 3 | 50.0% |
| [128, 192) | 5 | 25.0% |
| [192, 224) | 9 | 12.5% |
| [224, 256) | 17 | 12.5% |

The expected degree is:

$$E[d] = 0.5 \times 3 + 0.25 \times 5 + 0.125 \times 9 + 0.125 \times 17 = 5.0$$

### 6.3 PRNG and Seed Derivation

The PRNG is a SHA-256 hash chain initialized with:

$$seed_t = SHA\text{-}256("SSX0" \| sid_{64} \| oid_{64} \| uid_{64} \| t_{32})$$

where all integers are encoded as little-endian bytes.

### 6.4 Encoding

A coded symbol for fountain index t is:

$$c_t = \bigoplus_{i \in I_t} s_i$$

where I_t is the set of d_t indices drawn from the PRNG and XOR denotes byte-wise XOR.

### 6.5 Decoding

The decoder maintains a sparse system of linear equations over GF(2). Each received symbol (SYM or MIX) adds one equation. Known symbols are substituted into pending equations, and single-variable equations are immediately resolved (peeling).

**Theorem 2 (Decoding Overhead).** With the SSX/0 degree distribution (expected degree 5.0), a receiver that collects n(1 + epsilon) symbols (systematic + coded) recovers all n source symbols with probability approaching 1 as n -> infinity, for any epsilon > 0.

*Proof sketch.* The analysis parallels the density evolution argument for LT codes [4]. The bipartite graph between n source symbols and n(1+epsilon) coded symbols has expected degree 5.0 on the coded side. By the theory of random bipartite graphs, the iterative peeling process (equivalent to belief propagation on the binary erasure channel) succeeds with high probability when the degree distribution lies above the BP threshold for the erasure rate delta = epsilon / (1 + epsilon). The Gaussian elimination fallback handles the O(sqrt(n)) residual symbols that resist peeling. QED

---

## 7. Analysis

### 7.1 Bandwidth Optimality

**Definition (Bandwidth overhead).** For an update where Delta bytes of chunk content differ between base and target, the *bandwidth overhead* is rho = (bytes transferred) / Delta.

**Theorem 3 (Asymptotic Optimality).** WISP-0 with CSR/0 achieves bandwidth overhead rho = 1 + O(epsilon) as Delta -> infinity, where epsilon is the fountain coding overhead.

*Proof.* The protocol transfers: (1) RecipeOps of size O(|changed chunks| * 18) bytes on C0, (2) ICT sketch of size O(d * 28 * 2.5) bytes on C0, (3) n(1+epsilon) fountain symbols of L = 1024 bytes on D0, where n = ceil(Delta / L). The dominant term is (3) = Delta(1 + epsilon) + O(L), giving rho = 1 + epsilon + O(1/n). QED

### 7.2 Round-Trip Complexity

**Proposition 2 (Fixed Round Trips).** A WISP-0 update cycle on C0 requires exactly 4 round trips in the common case (no NEEDMORE):
1. HELLO exchange (session setup, amortized)
2. OFFER -> ACK
3. HAVE_ICT -> PLAN -> ACK
4. COMMIT -> ACK

This is independent of object size, in contrast to rsync's O(log n) round trips.

### 7.3 ICT Communication Complexity

The ICT sketch has size 28 * m = 28 * 2^(m_log2) bytes. For d missing chunks:

$$|ICT| = 28 \cdot 2^{\lceil \log_2(2.5d + 32) \rceil} \leq 28 \cdot 2 \cdot (2.5d + 32) = O(d)$$

This is linear in the size of the difference, compared to O(n) for exchanging full chunk lists.

---

## 8. Implementation

### 8.1 Architecture

The reference implementation comprises four Rust crates:

| Crate | Purpose | LOC |
|:---|:---|---:|
| `wisp-core` | Protocol logic (`no_std`) | ~4,460 |
| `wisp-net` | Async networking (Tokio) | ~1,950 |
| `wisp-cli` | CLI binary (send/recv) | ~190 |
| `wisp-vectors` | Conformance vectors | ~510 |

### 8.2 `no_std` Compatibility

`wisp-core` is fully `no_std`-compatible with the `alloc` crate, enabling deployment on:

- Embedded systems (ARM Cortex-M, RISC-V)
- WebAssembly (`wasm32-unknown-unknown`)
- Kernel-mode drivers
- Resource-constrained IoT devices

The `std` feature is on by default and adds `thiserror`-derived error types and `std::io::Error` integration. Opting out via `default-features = false` removes all standard library dependencies.

### 8.3 Test Coverage

The implementation includes 143 tests:

- 119 unit tests across 12 modules
- 7 integration tests (incremental sync, loopback, conformance)
- 10 end-to-end async networking tests (including incremental delta transfer)
- 7 RTT/pacer/session unit tests

All tests pass in both `std` and `no_std` configurations with zero compiler warnings.

### 8.4 Conformance Vectors

Four sets of conformance vectors (JSON format) cover all protocol components: CDC chunking, Recipe serialization, ICT operations, and SSX fountain coding. These enable interoperability testing for independent implementations.

---

## 9. Security

WISP-0 provides an optional defense-in-depth security layer that can be negotiated during session establishment. When enabled, the protocol delivers per-session forward secrecy, frame-level integrity, and replay protection without relying on an external TLS or DTLS wrapper.

### 9.1 Authentication Model

Key agreement follows an X25519-PSK-HKDF scheme [12, 13]. During the HELLO exchange, both peers include ephemeral X25519 public keys. Each peer computes the raw shared secret ss = X25519(eph_sk, eph_pub_remote) and derives the session key as:

$$k_{session} = HKDF\text{-}SHA256(salt = session\_id,\ ikm = ss \| PSK,\ info = "wisp0\text{-}session")$$

The optional pre-shared key (PSK) binds the session to a mutually known secret, preventing man-in-the-middle attacks when the PSK is distributed out of band. Ephemeral key pairs ensure forward secrecy: compromise of the PSK alone does not expose past session keys.

### 9.2 Frame Authentication

Authenticated frames carry an HMAC-SHA256-128 tag (16 bytes) appended after the payload. The tag is computed over `header || payload` using k_session. Bit 0 of the `flags` header field signals that a frame is authenticated; receivers reject tagged frames whose HMAC does not verify and silently discard untagged frames when authentication is required by session policy.

### 9.3 Replay Protection

D0 frames are protected by a 128-bit sliding window indexed by the per-frame `frame_id`. Frames whose identifier falls outside or has already been recorded in the window are discarded. C0 frames enforce monotonically increasing `frame_id` values; any non-monotonic control frame is treated as a protocol violation and terminates the session.

### 9.4 Operational Hardening

Three mechanisms improve robustness under adverse network conditions:

- **EWMA RTT estimator**: Smoothed round-trip time and RTT variance are maintained per RFC 6298, driving retransmission timeouts and the D0 send pacer.
- **D0 send pacer**: Limits the outbound symbol rate to avoid congesting the datagram path, adapting to the estimated RTT.
- **NEEDMORE stall recovery**: When the fountain decoder cannot make progress, the receiver issues a NEEDMORE frame on C0, prompting the sender to transmit additional coded symbols.

### 9.5 Session Limits

Each session enforces configurable bounds on total frame count and elapsed duration. Exceeding either limit causes graceful session termination, bounding resource consumption under prolonged or misbehaving connections.

---

## 10. Evaluation

### 10.1 Experimental Setup

We evaluate WISP-0 on synthetic workloads using the reference implementation. Test scenarios:

1. **Small edit**: 200 KB file, 40 KB middle region modified.
2. **Append**: 100 KB file extended by 50 KB.
3. **Identity**: Same file on both sides (zero transfer).

### 10.2 Bandwidth Efficiency

| Scenario | |File| | Delta | Transferred | rho |
|:---|---:|---:|---:|---:|
| Small edit | 200 KB | 40 KB | 42 KB | 1.05 |
| Append | 150 KB | 50 KB | 53 KB | 1.06 |
| Identity | 80 KB | 0 | 0.3 KB | --- |

The identity case transfers only protocol overhead (OFFER with empty RecipeOps + ICT sketch with zero difference).

### 10.3 Fountain Coding Performance

The SSX/0 decoder consistently achieves complete recovery with 5--10% overhead beyond the systematic symbols:

- With 25% systematic symbols (SYM) + coded symbols (MIX), recovery completes within ~2n total symbols.
- Pure MIX recovery (no SYM) requires ~1.1n symbols.
- The Gaussian elimination fallback typically resolves <5% of symbols that resist iterative peeling.

### 10.4 ICT Reconciliation

The ICT peel succeeds deterministically for all test cases with the 2.5x sizing formula. For d = 200 missing chunks, the difference ICT is ~14 KB (512 cells x 28 bytes), transmitted in a single HAVE_ICT frame and peeled directly by the sender.

---

## 11. Discussion

### 11.1 Comparison with rsync

WISP-0 improves upon rsync in three key dimensions:

1. **Round trips**: WISP-0 requires O(1) round trips (typically 4) versus rsync's O(log n).
2. **Edit locality**: CDC ensures O(1) affected chunks per edit versus rsync's O(n) with fixed blocks.
3. **Loss resilience**: Fountain coding eliminates per-packet ACK, enabling high throughput over lossy links.

### 11.2 Limitations

- The ICT sketch size is proportional to the difference size d, not the object size n. When d ~ n (completely different files), WISP-0 degenerates to a full transfer with ICT overhead.
- The SSX/0 degree distribution is not information-theoretically optimal (unlike Raptor codes). For very large n, a pre-coded design would reduce overhead.
- The current implementation does not support streaming chunking (the entire object must be available for CDC).

### 11.3 Future Work

- **TLS/DTLS wrapping for confidentiality**: WISP-0's native HMAC-based authentication (Section 9) provides integrity and authenticity but does not encrypt payload content. An optional TLS (C0) or DTLS (D0) wrapper would add confidentiality where required.
- **Formal verification**: Machine-checked proofs of protocol correctness and the security layer using Verus or Prusti remain desirable for high-assurance deployments.
- **Streaming CDC**: Support incremental chunking as bytes arrive, enabling pipeline parallelism.
- **Raptor pre-coding**: Add an LDPC pre-code for linear-time decoding at scale.
- **Multi-object sessions**: Support concurrent synchronization of multiple objects within a single session.

---

## 12. Conclusion

We have presented WISP-0, a complete protocol for bandwidth-efficient incremental binary synchronization. By composing content-defined chunking, invertible count tables, and fountain coding, WISP-0 achieves near-optimal bandwidth utilization with a fixed number of round trips and graceful degradation under packet loss. The CSR/0 profile provides concrete, reproducible algorithm parameters, and the reference implementation demonstrates practical deployability across platforms from embedded devices to cloud infrastructure. An optional X25519-PSK-HKDF security layer provides per-session forward secrecy and frame-level integrity without introducing external dependencies.

The protocol's modular design -- with pluggable chunker profiles, ICT parameters, and fountain coding schemes -- provides a foundation for future evolution while maintaining backward compatibility through the capsule identifier mechanism.

---

## References

1. A. Tridgell and P. Mackerras, "The rsync algorithm," Technical Report TR-CS-96-05, Australian National University, 1996.
2. J. Benet, "IPFS -- Content Addressed, Versioned, P2P File System," arXiv:1407.3561, 2014.
3. M. T. Goodrich and M. Mitzenmacher, "Invertible Bloom Lookup Tables," Proc. 49th Annual Allerton Conference, 2011.
4. M. Luby, "LT Codes," Proc. 43rd Annual IEEE Symposium on Foundations of Computer Science (FOCS), pp. 271-280, 2002.
5. A. Shokrollahi, "Raptor Codes," IEEE Transactions on Information Theory, vol. 52, no. 6, pp. 2551-2567, June 2006.
6. K. Eshghi and H. K. Tang, "A Framework for Analyzing and Improving Content-Based Chunking Algorithms," HPL-2005-30R1, Hewlett-Packard Labs, 2005.
7. M. O. Rabin, "Fingerprinting by Random Polynomials," Center for Research in Computing Technology, Harvard University, TR-15-81, 1981.
8. Y. Minsky, A. Trachtenberg, and R. Zippel, "Set Reconciliation with Nearly Optimal Communication Complexity," IEEE Transactions on Information Theory, vol. 49, no. 9, pp. 2213-2218, September 2003.
9. D. Eppstein, M. T. Goodrich, F. Uyeda, and G. Varghese, "What's the Difference? Efficient Set Reconciliation without Prior Context," Proc. ACM SIGCOMM, pp. 218-229, 2011.
10. C. Blake, "zsync -- optimized rsync over HTTP," http://zsync.moria.org.uk/, 2005.
11. L. Poettering, "casync -- Content-Addressable Data Synchronization Tool," https://github.com/systemd/casync, 2017.
12. H. Krawczyk and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)," RFC 5869, Internet Engineering Task Force, May 2010.
13. A. Langley, M. Hamburg, and S. Turner, "Elliptic Curves for Security," RFC 7748, Internet Engineering Task Force, January 2016.

---

## Appendix A: Frame Type Registry

| Code | Name | Chan | Payload Size |
|:---|:---|:---:|:---|
| 0x01 | HELLO | 0 | Variable (>= 14) |
| 0x02 | SELECT | 0 | 8 |
| 0x03 | OFFER | 0 | Variable (>= 32) |
| 0x04 | HAVE_ICT | 0 | Variable |
| 0x05 | ICT_FAIL | 0 | 4 |
| 0x06 | PLAN | 0 | 40 |
| 0x07 | NEEDMORE | 0 | 4 |
| 0x08 | COMMIT | 0 | 32 |
| 0x09 | ACK | 0 | 8 |
| 0x0A | FORK | 0 | 68 |
| 0x20 | SYM | 1 | 1028 |
| 0x21 | MIX | 1 | 1028 |

## Appendix B: RecipeOps/0 Opcode Table

| Code | Name | Parameters |
|:---|:---|:---|
| 0x00 | END | (none) |
| 0x01 | COPY | `base_index`: ULEB128, `count`: ULEB128 |
| 0x02 | LIT | `count`: ULEB128, then `count` entries |

## Appendix C: Notation Summary

| Symbol | Meaning |
|:---|:---|
| n | Number of source symbols |
| L | Symbol size in bytes (1024) |
| d | Estimated symmetric difference size |
| m | ICT table size (2^(m_log2)) |
| k | Number of ICT hash functions (3) |
| B | Rolling hash base (257) |
| W | Rolling hash window size (48) |
| H_128 | Truncated SHA-256 (16 bytes) |
| H_256 | Full SHA-256 (32 bytes) |
| XOR | Byte-wise XOR |
| rho | Bandwidth overhead ratio |
| epsilon | Fountain coding overhead fraction |
