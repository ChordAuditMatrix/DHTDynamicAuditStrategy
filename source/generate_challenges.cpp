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
 * @file generate_challenges.cpp
 * @brief Implementation of challenge generation for DHTDynamic strategy
 * @details Generates random challenge coefficients with blind commitment:
 *
 *          1. Validate request extension (fileId, userPublicParams, blockCount)
 *          2. Resolve block count from ext or stateStore
 *          3. Select random block indices {i_j} (1-based, consistent with SM9Static)
 *          4. Generate random non-zero coefficients ν_j ∈ Z_q*
 *          5. Verify Σν_j ≠ 0 (regenerate all if zero)
 *          6. Generate random scalar r, compute R = [r]·y (G2 blind commitment)
 *          7. For each selected block, get metadata from stateStore
 *          8. Build DHTDynamicChallenges{R, r, items=[{(i_j, ν_j, metadata_j)}], blockCount}
 *
 *          Key differences from SM9Static:
 *          - Adds R = [r]·y blind commitment on G2
 *          - Includes block metadata from stateStore in each challenge item
 *          - Uses 1-based blockIndex (consistent with SM9Static)
 *          - Requires fileId and userPublicParams in request extension
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-08
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/strategy.h"
#include "DHTDynamicAuditStrategy/request_ext.h"
#include "DHTDynamicAuditStrategy/params.h"
#include "DHTDynamicAuditStrategy/common.h"
#include "DHTDynamicAuditStrategy/challenges.h"
#include "DHTDynamicAuditStrategy/state_stores/versioned_block_metadata.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/dynamic_pdp_state_store.h"
#include "ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h"

#include <algorithm>
#include <random>
#include <unordered_set>

#include <spdlog/spdlog.h>

namespace CAMatrix::Audit::Strategies {

using namespace DHTDynamic;

CAMatrix::Audit::Messages::GenerateChallengesResult
DHTDynamicAuditStrategy::generateChallenges(
    const CAMatrix::Audit::Messages::GenerateChallengesRequest& input)
{
    CAMatrix::Audit::Messages::GenerateChallengesResult result;

    // ── Validate request extension ──
    auto ext = std::dynamic_pointer_cast<DHTDynamicChallengeRequestExt>(input.ext);
    if (!ext) {
        return result;
    }

    // ── Validate fileId (required for stateStore queries) ──
    if (ext->fileId.empty()) {
        spdlog::warn("DHTDynamicAuditStrategy::generateChallenges: fileId is empty");
        return result;
    }

    // ── Validate userPublicParams (required for y point to compute R = [r]·y) ──
    if (!ext->userPublicParams) {
        spdlog::warn("DHTDynamicAuditStrategy::generateChallenges: userPublicParams is null");
        return result;
    }

    // ── Validate stateStore injection ──
    if (!stateStore_) {
        spdlog::warn("DHTDynamicAuditStrategy::generateChallenges: stateStore not injected");
        return result;
    }

    // ── Check algorithm availability for random generation ──
    if (!algorithm_) {
        throw std::runtime_error("SM9BLS algorithm required for challenge generation");
    }

    // ── Resolve block count ──
    // Priority: ext->blockCount > stateStore->getBlockCount(fileId)
    const std::size_t blockCount = ext->blockCount != 0
        ? ext->blockCount
        : stateStore_->getBlockCount(ext->fileId);

    spdlog::debug("DHTDynamicAuditStrategy::generateChallenges: fileId={} blockCount={} "
                  "challengeCount={} usePseudoRandom={} seed.has_value={}",
                  ext->fileId, blockCount, ext->challengeCount,
                  ext->usePseudoRandom, ext->seed.has_value());

    // ── Create challenges container ──
    auto challenges = std::make_shared<DHTDynamicChallenges>();
    challenges->setBlockCount(blockCount);

    // ── Handle empty file ──
    if (blockCount == 0) {
        spdlog::warn("DHTDynamicAuditStrategy::generateChallenges: blockCount=0, "
                     "returning empty challenge items");
        result.challenges = challenges;
        return result;
    }

    // ── Determine challenge count ──
    const std::size_t count = std::min(
        ext->challengeCount == 0 ? blockCount : ext->challengeCount,
        blockCount);

    // ── Select random block indices (1-based) ──
    std::unordered_set<std::size_t> picked;
    picked.reserve(count);

    std::mt19937_64 rng(
        (ext->usePseudoRandom && ext->seed.has_value())
            ? ext->seed.value()
            : std::random_device{}());

    // 1-based index range: [1, blockCount] (consistent with SM9Static)
    std::uniform_int_distribution<std::size_t> dist(1, blockCount);

    while (picked.size() < count) {
        picked.insert(dist(rng));
    }

    spdlog::debug("DHTDynamicAuditStrategy::generateChallenges: picked {} indices "
                  "from range [1, {}]",
                  picked.size(), blockCount);

    // ── Generate challenge items with random non-zero coefficients ν_j ∈ Z_q* ──
    // ν_j must be non-zero because zero coefficients would nullify tag contributions.
    // Additionally, the sum ν = Σ(ν_j) must be non-zero (per spec §6.5).
    // If the sum is zero, regenerate all coefficients.
    std::vector<DHTDynamicChallenges::ChallengeItem> items;
    items.reserve(count);

    while (true) {
        SM9CryptoData nu{};  // ν = sum of challenge scalars
        items.clear();

        for (std::size_t index : picked) {
            DHTDynamicChallenges::ChallengeItem item;
            item.blockIndex = index;

            // Generate random scalar ν_j, retrying if zero (ν_j ≠ 0)
            SM9CryptoData v;
            do {
                auto randomBytes = algorithm_->generateRandom(v.size());
                if (randomBytes.size() != v.size()) {
                    throw std::runtime_error(
                        "Failed to generate random coefficient for challenge");
                }
                std::memcpy(v.data(), randomBytes.data(), v.size());
            } while (v.isZero());
            item.nu = v;

            nu.assign(*(nu + v));  // accumulate ν += ν_j
            items.push_back(item);
        }

        if (!nu.isZero()) {
            break;  // sum is non-zero, accept
        }
        spdlog::warn("DHTDynamicAuditStrategy::generateChallenges: sum of coefficients "
                     "is zero, regenerating all challenge coefficients");
    }

    // ── Generate random blind scalar r ∈ Z_q* ──
    SM9CryptoData r;
    do {
        auto randomBytes = algorithm_->generateRandom(r.size());
        if (randomBytes.size() != r.size()) {
            throw std::runtime_error("Failed to generate random scalar r for blind commitment");
        }
        std::memcpy(r.data(), randomBytes.data(), r.size());
    } while (r.isZero());

    // ── Compute R = [r]·y (G2 blind commitment) ──
    // y is the signing commitment from userPublicParams: y = [a]·g
    auto RPtr = ext->userPublicParams->y * r;
    auto R = std::static_pointer_cast<G2Point>(RPtr);

    // ── Populate metadata from stateStore for each challenge item ──
    for (auto& item : items) {
        auto metadata = stateStore_->getBlockMetadata(ext->fileId, item.blockIndex);
        // DynamicPdpStateStore returns shared_ptr<BlockMetadata> — cast to concrete type
        auto dynMeta = std::dynamic_pointer_cast<::CAMatrix::Audit::Strategies::DHTDynamic::VersionedBlockMetadata>(metadata);
        if (dynMeta) {
            item.metadata = *dynMeta;
        }
        // If cast fails, item.metadata keeps default values (version=1, timestamp=0)
    }

    // ── Build final challenges object ──
    challenges->setR(*R);   // G2Point R = [r]·y
    challenges->setR(r);    // SM9CryptoData r (scalar)
    challenges->items() = std::move(items);

    spdlog::debug("DHTDynamicAuditStrategy::generateChallenges: generated {} challenge items "
                  "with blockCount={} for fileId={}",
                  challenges->challengeCount(), blockCount, ext->fileId);

    result.challenges = challenges;
    // result.ext remains nullptr (DHTDynamicChallengeResultExt is empty)
    return result;
}

} // namespace CAMatrix::Audit::Strategies
