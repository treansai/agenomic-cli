# ATEP — Agentic Trajectory Event Protocol

ATEP is the binary, signed event log that captures an agent's history. The
CLI can produce, read, sign, and verify ATEP locally; the same wire format
is consumed by AgentLock Cloud.

## Two formats

1. **Canonical CBOR** (RFC 8949 §4.2) — what gets hashed and signed for a
   single event. Fields are encoded in struct order, parents are sorted
   before encoding, and the encoding is deterministic.
2. **Segment file** (`.atep`) — append-only on-disk container of multiple
   events.

## Segment binary layout (LE)

```
┌─────────────────────────────────────────┐
│ MAGIC          "ATEP"      4 B          │
│ VERSION        u16         2 B          │
│ FLAGS          u16         2 B          │
│ EVENT_COUNT    u32         4 B          │
│ FIRST_HLC                  16 B         │
│ LAST_HLC                   16 B         │
│ MERKLE_ROOT                32 B         │
│ ─────────────── 76-byte header          │
│ FRAMES (event_count of):                │
│   FRAME_LEN    u32         4 B          │
│   EVENT_BYTES  variable (CBOR canonical)│
│ INDEX_OFFSET   u64         8 B          │
│ INDEX_LEN      u64         8 B          │
│ CRC32                      4 B          │
│ MAGIC_TAIL     "PETA"      4 B          │
└─────────────────────────────────────────┘
```

The `MERKLE_ROOT` is BLAKE3 (with the `ATEP-NODE-v1\0` domain separator) over
the ordered list of `causal_hash` values.

## HLC

Events carry a `(physical_ms, logical, node_id)` Hybrid Logical Clock.
`Hlc::tick_after` follows Kulkarni et al., 2014.

## Causal hash

```
causal_hash = BLAKE3(
    "ATEP-v1\0"
    || u64_le(len(body))
    || body                   // canonical CBOR (header, payload), parents sorted
    || u32_le(len(parents))
    || sorted(parent_hash)*   // each parent is 32 bytes
)
```

## Signature

ed25519 over the 32-byte `causal_hash`. The signer's short key id
(`ed25519:<8-hex>`) is recorded in the event's `attestation` block.

## Store layout

```
.atep/
├── manifest.json
└── streams/
    ├── identity-00000001.atep
    ├── capability-00000001.atep
    └── ...
```

`agentlock atep init`, `append`, `verify`, `inspect`, and `replay-state`
operate on this layout.
