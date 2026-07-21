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
 * @file challenges.h
 * @brief DHTDynamic audit challenge types
 * @details Defines DHTDynamicChallenges, the concrete Challenges implementation
 *          for the DHT-based dynamic PDP scheme. Each challenge set contains:
 *          - items_: Vector of (blockIndex, ν_j, metadata) challenge items
 *          - R_: Blind commitment point on G2: R = [r]·y
 *          - r_: Random scalar used to generate R
 *          - blockCount_: Total number of blocks in the file
 *
 *          Challenge generation:
 *          1. Select random block indices {i_j}
 *          2. Generate random coefficients {ν_j}
 *          3. Compute R = [r]·y (blind commitment)
 *          4. Include block metadata from state store
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-06
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef CAMATRIX_DHT_DYNAMIC_CHALLENGES_H
#define CAMATRIX_DHT_DYNAMIC_CHALLENGES_H

#include "ChordAuditMatrixLib/implementations/audit/state_stores/versioned_block_metadata.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/data.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/points.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/challenges.h"

#include <cstddef>
#include <optional>
#include <vector>

namespace CAMatrix::Audit::Strategies::DHTDynamic {

/**
 * @class DHTDynamicChallenges
 * @brief Challenge set for DHTDynamic audit
 * @details Contains challenge items with block indices, random coefficients,
 *          block metadata, and a blind commitment point R = [r]·y on G2.
 */
class DHTDynamicChallenges final : public ::CAMatrix::Audit::Messages::Challenges {
public:
    /**
     * @struct ChallengeItem
     * @brief Single challenge item (block index, coefficient, metadata)
     */
    struct ChallengeItem {
        /** @brief Block index (1-based) */
        std::size_t blockIndex = 0;
        /** @brief Random coefficient ν_j */
        ::CAMatrix::Crypto::SM9BLS::SM9CryptoData nu{};
        /** @brief Block metadata at the time of challenge */
        ::CAMatrix::Audit::Core::VersionedBlockMetadata metadata{};
    };

    DHTDynamicChallenges() = default;
    ~DHTDynamicChallenges() override;

    // ── Accessors ──

    /**
     * @brief Get the blind commitment point R = [r]·y
     * @return const G2Point&, R point on G2
     */
    const ::CAMatrix::Crypto::SM9BLS::G2Point& R() const noexcept { return R_; }

    /**
     * @brief Set the blind commitment point
     * @param R [IN] New R point
     */
    void setR(const ::CAMatrix::Crypto::SM9BLS::G2Point& R) { R_ = R; }

    /**
     * @brief Get the random scalar r used to generate R
     * @return const SM9CryptoData&, Scalar r
     */
    const ::CAMatrix::Crypto::SM9BLS::SM9CryptoData& r() const noexcept { return r_; }

    /**
     * @brief Set the random scalar r
     * @param r [IN] New scalar
     */
    void setR(const ::CAMatrix::Crypto::SM9BLS::SM9CryptoData& r) { r_ = r; }

    /**
     * @brief Get the challenge items
     * @return const vector<ChallengeItem>&, Challenge items
     */
    const std::vector<ChallengeItem>& items() const noexcept { return items_; }

    /**
     * @brief Get mutable challenge items
     * @return vector<ChallengeItem>&, Mutable challenge items
     */
    std::vector<ChallengeItem>& items() noexcept { return items_; }

    /**
     * @brief Get total block count in the file
     * @return std::size_t, Block count
     */
    std::size_t blockCount() const noexcept { return blockCount_; }

    /**
     * @brief Set total block count
     * @param count [IN] Block count
     */
    void setBlockCount(std::size_t count) { blockCount_ = count; }

    /**
     * @brief Get number of challenge items
     * @return std::size_t, Challenge count
     */
    std::size_t challengeCount() const noexcept { return items_.size(); }

protected:
    /**
     * @brief Serialize challenges to binary archive
     * @param ar [OUT] cereal BinaryOutputArchive
     */
    void do_serialize(cereal::BinaryOutputArchive& ar) const override;

    /**
     * @brief Deserialize challenges from binary archive
     * @param ar [IN] cereal BinaryInputArchive
     */
    void do_deserialize(cereal::BinaryInputArchive& ar) override;

private:
    /** @brief Blind commitment point: R = [r]·y on G2 */
    ::CAMatrix::Crypto::SM9BLS::G2Point R_;

    /** @brief Random scalar r used to generate R */
    ::CAMatrix::Crypto::SM9BLS::SM9CryptoData r_;

    /** @brief Challenge items: {(i_j, ν_j, metadata_j)} */
    std::vector<ChallengeItem> items_;

    /** @brief Total number of blocks in the file */
    std::size_t blockCount_ = 0;
};

} // namespace CAMatrix::Audit::Strategies::DHTDynamic

#endif // CAMATRIX_DHT_DYNAMIC_CHALLENGES_H
