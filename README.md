# DHTDynamicAuditStrategy

DHT-based dynamic PDP (Provable Data Possession) audit strategy plugin for [ChordAuditMatrix](https://github.com/ChordAuditMatrix/ChordAuditMatrix).

## Overview

This is a built-in audit strategy implementing a **dynamic** PDP scheme using a Distributed Hash Table (DHT) as the state store. It supports block insert, update, and delete operations, making it suitable for mutable files.

The strategy implements the full 7-stage dynamic PDP pipeline:

```
┌───────────────────────────┐
│  1. initializeAlgorithm   │  Set up system parameters & public keys
│  2. generateKeys          │  Generate key pair (sk, pk)
│  3. generateTags          │  Compute authenticator tags σ_i for each block
│  4. generateChallenges    │  TPA generates random challenge set
│  5. generateProofs        │  CSP computes proof from challenged blocks
│  6. verifyProofs           │  TPA verifies proof against tags & challenges
│  7. maintenance            │  Handle Insert / Update / Delete on blocks
└───────────────────────────┘
```

**Strategy kind:** Dynamic — supports block-level updates via a `DynamicHashTableStateStore`.

## Building

### Standalone (for development / testing)

```bash
git clone --recurse-submodules git@github.com:ChordAuditMatrix/DHTDynamicAuditStrategy.git
cd DHTDynamicAuditStrategy
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)
```

This produces `libDHTDynamicAuditStrategy.so` (Linux) or `libDHTDynamicAuditStrategy.dylib` (macOS).

### In-tree (as ChordAuditMatrix submodule)

When built as part of the main project (`CAM_STANDALONE=OFF`), the shared library is placed directly into `dist/plugins/strategies/` with the correct RPATH.

## C-Linkage Factory Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `create_audit_strategy` | `AuditStrategy* create_audit_strategy() noexcept` | Allocates a new `DHTDynamicAuditStrategy` instance |
| `destroy_audit_strategy` | `void destroy_audit_strategy(AuditStrategy* p) noexcept` | Destroys a strategy instance (accesses protected destructor via friend) |

These are resolved by `AlgorithmRegistry` via `dlsym`/`GetProcAddress` at load time.

## State Stores

The DHT strategy requires a state store for tracking block versions. The following state stores are provided by CoreLib (remain in the core library, not in this plugin):

- `DynamicHashTableStateStore` — DHT-based state store for tracking block versions
- `InMemoryBlockMetadataCollection` — In-memory block metadata
- `VersionedBlockMetadata` — Per-block version tracking

## Configuration

Add to your server config (e.g., `config/audit.jsonc`):

```jsonc
{
  "custom_config": {
    "strategyDir": "plugins/strategies"
  }
}
```

The `AlgorithmHotLoadDecorator` will discover `DHTDynamicAuditStrategy.dylib` (or `.so`) in that directory.

## License

GPL-3.0 — see [LICENSE](LICENSE).
