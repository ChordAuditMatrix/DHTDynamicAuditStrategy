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
 * @file common.h
 * @brief Common helper functions and type aliases for DHTDynamic strategy
 * @details Convenience header that includes all DHTDynamic modules and provides
 *          type aliases and helper function declarations used across the
 *          DHTDynamic strategy implementation.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-06
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef CAMATRIX_DHT_DYNAMIC_COMMON_H
#define CAMATRIX_DHT_DYNAMIC_COMMON_H

// Include all DHTDynamic modules for convenient access
#include "DHTDynamicAuditStrategy/params.h"
#include "DHTDynamicAuditStrategy/request_ext.h"
#include "DHTDynamicAuditStrategy/state_stores/versioned_block_metadata.h"
#include "DHTDynamicAuditStrategy/maintain_types.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/dynamic_pdp_state_store.h"
#include "DHTDynamicAuditStrategy/state_stores/dynamic_hash_table_state_store.h"
#include "DHTDynamicAuditStrategy/tags.h"
#include "DHTDynamicAuditStrategy/challenges.h"
#include "DHTDynamicAuditStrategy/proves.h"

// Include SM9BLS crypto layer
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/algorithm.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/strategy.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/data.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/points.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/gt_element.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/hash_utils.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/keys/public_key.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/keys/private_key.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/keys/key_pair.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace CAMatrix::Audit::Strategies {

// ── DHTDynamic sub-namespace: type aliases and helper functions ──

namespace DHTDynamic {

// ── SM9BLS crypto type aliases ──

using SM9BLSAlgorithm = ::CAMatrix::Crypto::SM9BLS::SM9BLSAlgorithm;
using SM9BLSCryptoStrategy = ::CAMatrix::Crypto::SM9BLS::SM9BLSCryptoStrategy;
using SM9CryptoData = ::CAMatrix::Crypto::SM9BLS::SM9CryptoData;
using CryptoArray = ::CAMatrix::Crypto::SM9BLS::CryptoArray;
using CryptoDataPtr = ::CAMatrix::Crypto::SM9BLS::CryptoDataPtr;
using G1Point = ::CAMatrix::Crypto::SM9BLS::G1Point;
using G2Point = ::CAMatrix::Crypto::SM9BLS::G2Point;
using G1PointPtr = ::CAMatrix::Crypto::SM9BLS::G1PointPtr;
using G2PointPtr = ::CAMatrix::Crypto::SM9BLS::G2PointPtr;
using SM9GTElement = ::CAMatrix::Crypto::SM9BLS::SM9GTElement;
using SM9GTElementPtr = ::CAMatrix::Crypto::SM9BLS::SM9GTElementPtr;

// ── DHTDynamic parameter types are already in this namespace ──
// (DHTDynamicAlgoPublicParams, DHTDynamicPublicParams, etc. are defined
//  in params.h within CAMatrix::Audit::Strategies::DHTDynamic, so no
//  additional aliases needed — they are directly accessible here.)

/**
 * @brief Compute per-block hash point for tag generation
 * @details H(fileId‖i‖metadata) ∈ G₁ — hash-to-curve of fileId, blockIndex, and serialized metadata
 *          σ_i = [a]·(H(fileId‖i‖metadata_i) + m_i·u)
 *          The fileId and blockIndex ensure uniqueness across files and blocks.
 *          The metadata (version + timestamp) is serialized via CryptoSerializable::serialize()
 *          and appended to the hash input. Any change to the block's metadata (e.g., version
 *          increment during update) will produce a different hash point, making stale
 *          tags detectable.
 * @param fileId [IN] File identifier
 * @param blockIndex [IN] Block index (1-based, consistent with SM9Static)
 * @param metadata [IN] Block metadata (version, timestamp)
 * @return G1Point, H = hashToCurve(fileId‖i‖metadata.serialize())
 */
G1Point computeBlockHash(const std::string& fileId, std::size_t blockIndex,
                          const ::CAMatrix::Audit::Core::VersionedBlockMetadata& metadata);

/**
 * @brief Segment size for block encoding (sizeof(sm9_z256_t) = 32 bytes)
 * @details Each block is split into 32-byte segments; each segment is directly
 *          interpreted as a scalar (sm9_z256_t) for elliptic curve operations.
 *          This prevents the CSP from caching only hash digests to pass audit —
 *          the CSP must retain the actual block data to reconstruct per-segment scalars.
 */
constexpr std::size_t segmentSize = 32;

/**
 * @brief Accumulate block segments as G₁ point: Σ[segment_j]·basePoint
 * @details Splits the block into 32-byte segments, interprets each segment as a
 *          scalar (sm9_z256_t via direct memcpy), and computes the elliptic curve
 *          point sum: result = Σ_{j=0}^{k-1} [segment_j]·basePoint ∈ G₁.
 *
 *          This replaces the old blockToScalar(block) approach which used
 *          hashToScalar(wholeBlock) — a single hash that the CSP could cache
 *          (32 bytes) instead of storing the full block (typically 1024 bytes),
 *          defeating PDP's purpose.
 *
 *          With segment-based encoding, the CSP must retain every 32-byte segment
 *          to reconstruct the proof, because each segment independently contributes
 *          to the G₁ point accumulation.
 * @param block [IN] Raw block data (typically 1024 bytes)
 * @param basePoint [IN] G₁ base point (u for DHTDynamic)
 * @return G1Point, Σ[segment_j]·basePoint
 */
G1Point accumulateBlockSegmentsG1(const std::vector<std::uint8_t>& block, const G1Point& basePoint);

/**
 * @brief Accumulate block segments as scalar sum: Σ segment_j (mod n)
 * @details Splits the block into 32-byte segments, interprets each segment as a
 *          scalar (sm9_z256_t via direct memcpy), and computes the scalar sum:
 *          result = Σ_{j=0}^{k-1} segment_j (mod n).
 *
 *          Used in proof generation: M = Σ(ν_j · Σ segment_j) = Σ Σ(ν_j · segment_j).
 *          The inner sum Σ segment_j is computed by this function; the outer weighted
 *          sum Σ(ν_j · ...) is computed in generate_proofs.cpp.
 * @param block [IN] Raw block data (typically 1024 bytes)
 * @return SM9CryptoData, Σ segment_j (mod n)
 */
SM9CryptoData accumulateBlockSegmentsScalar(const std::vector<std::uint8_t>& block);

/**
 * @brief Convert data block to scalar value (DEPRECATED — use segment-based encoding)
 * @details H₂(block) → scalar m_i for linear combination in proof.
 *          This function is vulnerable to the hash-caching attack: the CSP can
 *          cache the 32-byte hash output instead of storing the full block.
 *          Use accumulateBlockSegmentsG1() or accumulateBlockSegmentsScalar() instead.
 * @deprecated Use accumulateBlockSegmentsG1() for tag generation and
 *             accumulateBlockSegmentsScalar() for proof generation.
 * @param block [IN] Raw block data
 * @return SM9CryptoData, Scalar representation of block
 */
SM9CryptoData blockToScalar(const std::vector<std::uint8_t>& block);

/**
 * @brief Compute challenge coefficient hash
 * @details H₃(challenge) → scalar ν_j for challenge weighting
 * @param seed [IN] Challenge seed data
 * @return SM9CryptoData, Scalar coefficient
 */
SM9CryptoData challengeToScalar(const CryptoArray& seed);

} // namespace DHTDynamic

} // namespace CAMatrix::Audit::Strategies

#endif // CAMATRIX_DHT_DYNAMIC_COMMON_H
