/*
 * Copyright (C) 2021-2026, Dylan Liu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file common.cpp
 * @brief Common helper functions implementation for DHTDynamic strategy
 * @details Uses SM9BLS hash functions (hashToCurve, hashToScalar, hashChallenge)
 *          for the dynamic PDP audit scheme. These helpers wrap the low-level
 *          SM9BLS crypto operations into strategy-level abstractions.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-08
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/common.h"

#include <algorithm>
#include <cstring>

namespace CAMatrix::Audit::Strategies {
namespace DHTDynamic {

// ─────────────────────────────────────────────────────────────────────────────
// computeBlockHash: H(fileId‖i‖metadata) ∈ G₁
// ─────────────────────────────────────────────────────────────────────────────

G1Point computeBlockHash(const std::string& fileId, std::size_t blockIndex,
                          const ::CAMatrix::Audit::Strategies::DHTDynamic::VersionedBlockMetadata& metadata)
{
    // Build input: fileId || blockIndex (big-endian 8 bytes) || metadata.serialize()
    // The fileId and blockIndex ensure uniqueness across files and blocks.
    // The metadata (version + timestamp) is serialized via CryptoSerializable::serialize()
    // and appended to the hash input. Any change to metadata (e.g., version increment)
    // produces a different hash point, making stale tags detectable.
    auto serialized = metadata.serialize();
    CryptoArray data;
    data.reserve(fileId.size() + sizeof(std::uint64_t) + serialized.size());
    data.insert(data.end(), fileId.begin(), fileId.end());
    // Append blockIndex as big-endian uint64
    for (int i = static_cast<int>(sizeof(std::uint64_t)) - 1; i >= 0; --i) {
        data.push_back(static_cast<std::uint8_t>((blockIndex >> (i * 8)) & 0xFF));
    }
    // Append serialized metadata
    data.insert(data.end(), serialized.begin(), serialized.end());
    return CAMatrix::Crypto::SM9BLS::hashToCurve(data);
}

// ─────────────────────────────────────────────────────────────────────────────
// accumulateBlockSegmentsG1: Σ[segment_j]·basePoint ∈ G₁
// ─────────────────────────────────────────────────────────────────────────────

G1Point accumulateBlockSegmentsG1(const std::vector<std::uint8_t>& block, const G1Point& basePoint)
{
    // Split block into 32-byte segments; each segment is directly interpreted
    // as a scalar (sm9_z256_t) via memcpy. Then compute [Σ segment_j (mod n)]·basePoint.
    //
    // Security rationale: the CSP must retain every 32-byte segment of the block
    // to reconstruct this G₁ point. Caching a single 32-byte hash of the whole
    // block is insufficient — the CSP needs all ~32 segments (for a 1024-byte block).
    //
    // Implementation note: We compute the scalar sum first via
    // accumulateBlockSegmentsScalar (which uses sm9_z256_modn_add), then do a
    // single point multiplication. This guarantees that tag generation (G₁
    // point) and proof generation (scalar M) use exactly the same scalar value,
    // avoiding any mismatch between sm9_z256_point_mul and sm9_z256_modn_add
    // when raw 32-byte segment values exceed the curve order n.

    const SM9CryptoData scalarSum = accumulateBlockSegmentsScalar(block);
    auto resultPtr = basePoint * scalarSum;
    return *std::static_pointer_cast<G1Point>(resultPtr);
}

// ─────────────────────────────────────────────────────────────────────────────
// accumulateBlockSegmentsScalar: Σ segment_j (mod n)
// ─────────────────────────────────────────────────────────────────────────────

SM9CryptoData accumulateBlockSegmentsScalar(const std::vector<std::uint8_t>& block)
{
    // Split block into 32-byte segments; each segment is directly interpreted
    // as a scalar (sm9_z256_t) via memcpy. Then compute Σ segment_j (mod n).
    //
    // Used in proof generation: M = Σ(ν_j · Σ segment_j).
    // The inner sum is computed here; the outer weighted sum is in generate_proofs.cpp.
    //
    // Note: SM9CryptoData::operator+ uses sm9_z256_modn_add which correctly
    // handles values > n, so raw 32-byte values are safe.

    const std::size_t segmentCount = (block.size() + segmentSize - 1) / segmentSize;

    SM9CryptoData sum(uint64_t(0));  // zero-initialized

    for (std::size_t j = 0; j < segmentCount; ++j) {
        SM9CryptoData segment;
        const std::size_t offset = j * segmentSize;
        const std::size_t copySize = std::min(segmentSize, block.size() - offset);
        std::memcpy(segment.data(), block.data() + offset, copySize);
        if (copySize < segmentSize) {
            std::memset(segment.data() + copySize, 0, segmentSize - copySize);
        }

        auto newSum = sum + segment;  // sm9_z256_modn_add
        if (newSum) {
            sum.assign(*newSum);
        }
    }

    return sum;
}

// ─────────────────────────────────────────────────────────────────────────────
// blockToScalar: H₂(block) → scalar m_i  [DEPRECATED]
// ─────────────────────────────────────────────────────────────────────────────

SM9CryptoData blockToScalar(const std::vector<std::uint8_t>& block)
{
    // DEPRECATED: This function uses hashToScalar(wholeBlock) which allows the
    // CSP to cache only the 32-byte hash output instead of storing the full block.
    // Use accumulateBlockSegmentsG1() or accumulateBlockSegmentsScalar() instead.
    //
    // Kept for backward compatibility during transition.
    CryptoArray payload(block.begin(), block.end());
    return CAMatrix::Crypto::SM9BLS::hashToScalar(payload);
}

// ─────────────────────────────────────────────────────────────────────────────
// challengeToScalar: H₃(challenge) → scalar ν_j
// ─────────────────────────────────────────────────────────────────────────────

SM9CryptoData challengeToScalar(const CryptoArray& seed)
{
    // H₃(challenge) = hashChallenge(seed) ∈ Z_q
    // Used for challenge coefficient generation
    return CAMatrix::Crypto::SM9BLS::hashChallenge(seed);
}

} // namespace DHTDynamic
} // namespace CAMatrix::Audit::Strategies
