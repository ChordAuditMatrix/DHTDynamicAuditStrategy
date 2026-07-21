# AuditStrategyTemplate

A template repository for implementing custom audit strategies as shared-library plugins for the [ChordAuditMatrix](https://github.com/ChordAuditMatrix/ChordAuditMatrix) system.

## Overview

ChordAuditMatrix uses a **hot-load** architecture: audit strategies are compiled as shared libraries (`.so` / `.dylib`) and loaded at runtime via `dlopen`/`dlsym`. This template provides a ready-to-build skeleton that you can fork, implement, and drop into the system.

The template depends on [CoreLib](https://github.com/ChordAuditMatrix/CoreLib), which is included as a git submodule and provides all base classes, message types, and cryptographic primitives.

## Architecture

Every audit strategy implements a **7-stage PDP (Provable Data Possession) pipeline**:

```
┌───────────────────────┐
│  1. initializeAlgorithm│  Set up system parameters & public keys
│  2. generateKeys       │  Generate key pair (sk, pk)
│  3. generateTags       │  Compute authenticator tags σ_i for each block
│  4. generateChallenges │  TPA generates random challenge set
│  5. generateProofs     │  CSP computes proof from challenged blocks
│  6. verifyProofs       │  TPA verifies proof against tags & challenges
└───────────────────────┘
```

Dynamic strategies add a **7th stage**:

```
│  7. maintenance        │  Handle Insert / Update / Delete on blocks
```

### Class Hierarchy

```
PluggableAlgorithm          (CAMatrix::Base)
  └── AuditStrategy         (CAMatrix::Audit::Core)
        ├── StaticAuditStrategy   — kind() = Static, no maintenance()
        └── DynamicAuditStrategy  — kind() = Dynamic, has maintenance() + state store
```

### Strategy Kinds

| Kind | Base Class | Use Case |
|------|-----------|----------|
| **Static** | `StaticAuditStrategy` | File is immutable after tagging (e.g., SM9-Static PDP) |
| **Dynamic** | `DynamicAuditStrategy` | File supports block insert/update/delete (e.g., DHT-Dynamic PDP) |

### Capabilities Bitmask

```cpp
enum class Capabilities : uint32_t {
    BatchVerify            = 1,      // Supports multi-file batch verification
    IdentityAuthentication = 2,      // Supports identity-based authentication
    DynamicUpdate          = 4,      // Supports dynamic block operations
};
```

## Quick Start

### 1. Clone with Submodules

```bash
git clone --recurse-submodules git@github.com:ChordAuditMatrix/AuditStrategyTemplate.git
cd AuditStrategyTemplate
```

If you already cloned without `--recurse-submodules`:

```bash
git submodule update --init --recursive
```

### 2. Build

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build . -j$(nproc)
```

This produces `libAuditStrategyTemplate.so` (or `.dylib` on macOS).

### 3. Install into ChordAuditMatrix

Copy the shared library to the algorithm plugin directory configured in your ChordAuditMatrix deployment:

```bash
cp libAuditStrategyTemplate.so /path/to/chordauditmatrix/plugins/
```

The `AlgorithmRegistry` will discover it via the C-linkage factory functions.

## Implementing Your Strategy

### Choose a Base Class

- **Static PDP** → inherit `CAMatrix::Audit::Core::StaticAuditStrategy`
- **Dynamic PDP** → inherit `CAMatrix::Audit::Core::DynamicAuditStrategy`

### Required Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `algorithmType()` | Unique algorithm identifier (e.g., `"MyCustomPDP"`) | `std::string` |
| `version()` | Semantic version string | `std::string` |
| `caps()` | Supported capabilities bitmask | `Capabilities` |
| `setAlgorithm(algo)` | Inject a `CryptoGeneralAlgorithmPtr` | `void` |
| `initializeAlgorithm(req)` | Initialize system parameters | `InitializeAlgorithmResult` |
| `generateKeys(req)` | Generate key pair | `GenerateKeysResult` |
| `generateTags(req)` | Compute authenticator tags | `GenerateTagsResult` |
| `generateChallenges(req)` | Generate random challenges | `GenerateChallengesResult` |
| `generateProofs(req)` | Compute proof from challenged blocks | `GenerateProofsResult` |
| `verifyProofs(req)` | Verify proof correctness | `VerifyProofsResult` |
| `createRequest(op, ctx, raw)` | Convert `RawInput` → typed `Request` | `AuditRequestVariantPtr` |
| `artifactFactory()` | Factory for creating Tags, Challenges, Proves, etc. | `const AuditStrategyArtifactFactory&` |

**Dynamic strategies** must also implement:

| Method | Description | Returns |
|--------|-------------|---------|
| `stateMaintenanceParty()` | Which party handles state (TPA, CSP, etc.) | `StateMaintenanceParty` |
| `maintenance(req)` | Handle block Insert/Update/Delete | `MaintainResult` |

### C-Linkage Factory Functions

Every plugin shared library **must** export these two symbols:

```cpp
extern "C" CAMatrix::Audit::Core::AuditStrategy* create_audit_strategy() noexcept
{
    return new YourStrategy();
}

extern "C" void destroy_audit_strategy(CAMatrix::Audit::Core::AuditStrategy* p) noexcept
{
    delete p;
}
```

These are resolved by `AlgorithmRegistry` at load time via `dlsym`.

### Request / Result Types

All pipeline stages use **strongly-typed** Request/Result structs (not variant maps):

| Stage | Request | Result |
|-------|---------|--------|
| Init | `InitializeAlgorithmRequest` | `InitializeAlgorithmResult` |
| Keys | `GenerateKeysRequest` | `GenerateKeysResult` |
| Tags | `GenerateTagsRequest` | `GenerateTagsResult` |
| Challenges | `GenerateChallengesRequest` | `GenerateChallengesResult` |
| Proofs | `GenerateProofsRequest` | `GenerateProofsResult` |
| Verify | `VerifyProofsRequest` | `VerifyProofsResult` |
| Maintain | `MaintainRequest` | `MaintainResult` |

Each Result contains an `ok` flag, a `reason` string (on failure), and an `ext` field for algorithm-specific extensions via `StageExtBase`.

### Artifact Factory

The `artifactFactory()` method returns a reference to an `AuditStrategyArtifactFactory` that creates typed artifacts:

```cpp
enum class AuditArtifactKind : uint8_t {
    AlgorithmPublicParams,
    AlgorithmPrivateParams,
    UserPublicParams,
    UserPrivateParams,
    Tag,
    Challenges,
    Proves,
    DynamicBlockMetadata,
};
```

You must implement a concrete factory subclass that maps each `AuditArtifactKind` to your algorithm's specific types (e.g., `SM9Tag`, `DHTChallenges`).

### RawInput → Request Conversion

The `createRequest()` method converts unstructured input into a typed Request:

```cpp
AuditRequestVariantPtr createRequest(
    AuditOperation op,                    // Which pipeline stage
    const AuditOperationContext& context,  // Results from previous stages
    const RawInput& rawInput              // Raw data (JSON, binary, or custom)
) override;
```

`RawInput` supports three input formats:
- **JSON** — `rawInput.requireJson(op)` parses and returns `Json::Value`
- **Binary** — `rawInput.requireBinary(op)` returns `shared_ptr<vector<uint8_t>>`
- **Custom** — `rawInput.requireCustom<T>(op)` returns `shared_ptr<T>`

## CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `CAM_BUILD_BENCHMARK` | `OFF` | Build benchmarks |
| `CAM_BUILD_TESTS` | `OFF` | Build tests |
| `CAM_GENERATE_DOCS` | `OFF` | Generate Doxygen documentation |

Options propagate automatically via CMake cache — no `CACHE FORCE` needed.

## Project Structure

```
AuditStrategyTemplate/
├── CMakeLists.txt
├── README.md
├── .gitignore
├── .gitmodules
├── .cmake/
│   └── Doxyfile.in
├── 3rdparty/
│   └── CoreLib/          ← git submodule
├── include/
│   └── NewAuditStrategy/
│       └── new_audit_strategy.h
└── source/
    └── new_audit_strategy.cpp
```

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
