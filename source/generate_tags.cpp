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
 * @file generate_tags.cpp
 * @brief Implementation of tag generation for DHTDynamic strategy
 * @details Tag formula: σ_i = [a]·[H₁(fileId‖i‖version‖timestamp) + m_i·u] (BLS signature with signing scalar a)
 *
 *          For each block i (1-based logical, 0-based storage):
 *          1. Compute H_i = hashToCurve(fileId‖i‖version‖timestamp) ∈ G₁
 *          2. Compute m_i = hashToScalar(block_i) ∈ Z_q
 *          3. Compute [m_i]·u ∈ G₁ (message commitment)
 *          4. Compute H_i + [m_i]·u ∈ G₁ (hash + message commitment)
 *          5. Compute σ_i = [a]·(H_i + [m_i]·u) (scalar × G₁ point)
 *          6. Create DHTDynamicTag{sigma=σ_i}
 *          7. Store tag in Tags container (0-based index, aligned with SM9Static)
 *
 *          Initial metadata: version=1, timestamp=now() (epoch seconds).
 *          When a block is updated, the Admin must regenerate the tag with the new
 *          version/timestamp via generateTags() before calling maintenance().
 *
 *          Note: generateTags auto-registers the file and any missing blocks
 *          into the stateStore, so tags and stateStore metadata stay consistent.
 *          If the file does not exist in stateStore, an empty file entry is
 *          created and blocks are registered on-demand. stateStore injection
 *          is required — generateTags throws if stateStore is not set.
 *
 *          Unlike SM9Static (σ_i = [x_ID](W_i + [m_i]U) + D_ID),
 *          DHTDynamic uses a BLS-based signature with message commitment:
 *          σ_i = [a]·[H_i + m_i·u], where a is the BLS signing scalar, u is the proof binding point.
 *          This makes tags content-dependent — updating block content
 *          requires regenerating the tag.
 *
 * @author Dylan Liu
 * @version 1.1.0
 * @date 2026-07-09
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/strategy.h"
#include "DHTDynamicAuditStrategy/request_ext.h"
#include "DHTDynamicAuditStrategy/params.h"
#include "DHTDynamicAuditStrategy/common.h"
#include "DHTDynamicAuditStrategy/tags.h"
#include "DHTDynamicAuditStrategy/state_stores/versioned_block_metadata.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/dynamic_pdp_state_store.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/in_memory_tags.h"
#include "ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h"

#include <memory>

namespace CAMatrix::Audit::Strategies {

using namespace DHTDynamic;

CAMatrix::Audit::Messages::GenerateTagsResult
DHTDynamicAuditStrategy::generateTags(
    const CAMatrix::Audit::Messages::GenerateTagsRequest& input)
{

    CAMatrix::Audit::Messages::GenerateTagsResult result;

    // ── Validate request extension ──
    auto ext = std::dynamic_pointer_cast<DHTDynamicTagsGenRequestExt>(input.ext);
    if (!ext) {
        return result;
    }

    // ── Validate fileId ──
    if (ext->fileId.empty()) {
        return result;
    }

    // ── Validate blocks source ──
    if (!input.blocks) {
        return result;
    }

    // ── Validate user private params ──
    if (!ext->userPrivateParams) {
        return result;
    }

    // ── Validate user public params (need u for message commitment) ──
    if (!ext->userPublicParams) {
        return result;
    }

    const std::size_t blockCount = input.blocks->availableBlockCount();
    const SM9CryptoData& a = ext->userPrivateParams->a;
    const G1Point& u = ext->userPublicParams->u;

    // ── Determine which block indices to generate tags for ──
    // When targetBlockIndices is set, only generate tags for the specified
    // 1-based global block indices.  When unset, generate for all blocks in
    // the source (backward compatible default behaviour).
    std::vector<std::size_t> targetIndices;
    if (input.targetBlockIndices.has_value()) {
        targetIndices = input.targetBlockIndices.value();
    } else {
        // Default: generate tags for all blocks in the source
        targetIndices.reserve(blockCount);
        for (std::size_t i = 0; i < blockCount; ++i) {
            targetIndices.push_back(input.blocks->globalBlockStartIndex() + i + 1);
        }
    }

    // ── Create tag container ──
    auto tags = std::make_shared<CAMatrix::Audit::Messages::InMemoryTags>(
        []() -> std::shared_ptr<CAMatrix::Audit::Messages::Tag> {
            return std::make_shared<DHTDynamicTag>();
        });
    tags->reserve(targetIndices.size());

    // ── Validate stateStore injection ──
    // stateStore is required — tag metadata must come from (and be
    // registered in) the stateStore so that tags, challenges, and
    // maintenance all read from the same source of truth.
    if (!stateStore_) {
        throw std::runtime_error("DHTDynamic generateTags: stateStore not injected");
    }

    // ── Ensure file is registered in stateStore ──
    // When the file is not yet in the stateStore (e.g., initial upload),
    // auto-register it so that tags and stateStore stay consistent.
    // We create an empty file (addFile) and register individual blocks
    // on-demand inside the loop via collection->set(), which writes
    // directly without shift semantics.  insertBlock() is unsuitable here
    // because it shifts existing entries (maintenance semantics, not
    // fresh registration) and is order-dependent on targetIndices.
    if (!stateStore_->hasFile(ext->fileId)) {
        stateStore_->addFile(ext->fileId);
    }

    // ── Generate tags for each target block index ──
    for (const auto blockIndex : targetIndices) {
        // Read per-block metadata from stateStore; auto-register if missing.
        std::shared_ptr<CAMatrix::Audit::Core::BlockMetadata> meta;
        try {
            meta = stateStore_->getBlockMetadata(ext->fileId, blockIndex);
        } catch (const std::runtime_error&) {
            // Block not in stateStore — auto-register by writing directly
            // to the collection at the correct 0-based index.
            // This uses the same metadata values as the stateStore's
            // factory (version=1, timestamp=now) so tag and stateStore
            // match exactly.
            const auto now = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            meta = std::make_shared<CAMatrix::Audit::Strategies::DHTDynamic::VersionedBlockMetadata>(1, now);
            auto collection = stateStore_->getBlockMetadataCollection(ext->fileId);
            collection->set(blockIndex - 1, meta);
        }

        // Cast outside try-catch so a type mismatch propagates as an error
        // instead of being swallowed by the auto-register catch above.
        auto dynMeta = std::dynamic_pointer_cast<CAMatrix::Audit::Strategies::DHTDynamic::VersionedBlockMetadata>(meta);
        if (!dynMeta) {
            throw std::runtime_error("DHTDynamic generateTags: block " +
                std::to_string(blockIndex) + " metadata is not VersionedBlockMetadata");
        }
        const CAMatrix::Audit::Strategies::DHTDynamic::VersionedBlockMetadata metadata = *dynMeta;

        // H_i = hashToCurve(fileId‖blockIndex‖metadata.serialize()) ∈ G₁ — per-block hash point
        // The fileId and blockIndex ensure uniqueness across files and blocks.
        // The metadata (version + timestamp) is serialized and hashed to curve.
        // Any change to metadata (e.g., version increment) produces a different hash,
        // making stale tags detectable.
        const G1Point H_i = DHTDynamic::computeBlockHash(ext->fileId, blockIndex, metadata);

        // Compute the 0-based local index within the block source
        const std::size_t localIndex = blockIndex - 1 - input.blocks->globalBlockStartIndex();

        // Block content — split into 32-byte segments for tag generation
        const std::vector<std::uint8_t> block = input.blocks->block(localIndex);

        // Σ[segment_j]·u ∈ G₁ — segment-based message commitment point
        // Each 32-byte segment is interpreted as a scalar (sm9_z256_t) and
        // multiplied with u, then accumulated via point addition.
        // This prevents the CSP from caching only a hash digest to pass audit.
        const G1Point segmentSum = DHTDynamic::accumulateBlockSegmentsG1(block, u);

        // H_i + Σ[segment_j]·u ∈ G₁ — hash + segment-based message commitment
        auto sum = H_i + segmentSum;
        auto sumPoint = std::static_pointer_cast<G1Point>(sum);

        // σ_i = [a]·(H_i + Σ[segment_j]·u) — BLS signature with signing scalar a
        auto sigmaPtr = *sumPoint * a;
        auto sigma = std::static_pointer_cast<G1Point>(sigmaPtr);

        // Create DHTDynamicTag{sigma=σ_i} (Tag only contains signature, not metadata)
        auto tag = std::make_shared<DHTDynamicTag>(*sigma);

        // Store tag at global 0-based index (= blockIndex - 1) so the tags
        // collection carries position information: tag at index N corresponds
        // to global blockIndex N+1.  When globalBlockStartIndex=0 this is
        // identical to the old 0-based behaviour.
        tags->set(blockIndex - 1, tag);
    }

    result.tags = tags;
    // result.ext remains nullptr (DHTDynamicTagsGenResultExt is empty)
    return result;
}

} // namespace CAMatrix::Audit::Strategies
