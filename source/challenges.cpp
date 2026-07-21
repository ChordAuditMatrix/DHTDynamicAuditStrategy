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
 * @file challenges.cpp
 * @brief DHTDynamic audit challenge serialization implementation
 * @details Serializes DHTDynamicChallenges using cereal BinaryArchive.
 *          Format:
 *          - R_: G2Point raw struct (SM9_Z256_TWIST_POINT)
 *          - r_: SM9CryptoData binary field
 *          - blockCount_: uint64
 *          - itemCount_: uint64
 *          - Per item: blockIndex (uint64) + nu (binary data) + metadata (version + timestamp)
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-08
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/challenges.h"

#include "ChordAuditMatrixLib/implementations/crypto/sm9/points.h"
#include "ChordAuditMatrixLib/interfaces/crypto/serializable.h"

#include <cereal/archives/binary.hpp>

namespace CAMatrix::Audit::Strategies::DHTDynamic {

DHTDynamicChallenges::~DHTDynamicChallenges() = default;

void DHTDynamicChallenges::do_serialize(cereal::BinaryOutputArchive& ar) const
{
    // R_: G2Point → raw struct
    auto rRaw = R_.toRawStruct();
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_challenges_R", rRaw);

    // r_: SM9CryptoData → binary field
    CEREAL_SERIALIZE_BINARY_FIELD(ar, "dht_dynamic_challenges_r", r_);

    // blockCount_
    CEREAL_NVP_SERIALIZE(ar, "blockCount", blockCount_);

    // items_
    std::size_t itemCount = items_.size();
    CEREAL_NVP_SERIALIZE(ar, "itemCount", itemCount);
    for (const auto& item : items_) {
        CEREAL_NVP_SERIALIZE(ar, "blockIndex", item.blockIndex);
        ar(cereal::binary_data(item.nu.data(), item.nu.size()));
        CEREAL_NVP_SERIALIZE(ar, "version", item.metadata.version);
        CEREAL_NVP_SERIALIZE(ar, "timestamp", item.metadata.timestamp);
    }
}

void DHTDynamicChallenges::do_deserialize(cereal::BinaryInputArchive& ar)
{
    // R_: G2Point ← raw struct
    SM9_Z256_TWIST_POINT rRaw{};
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_challenges_R", rRaw);
    R_ = CAMatrix::Crypto::SM9BLS::G2Point(&rRaw);

    // r_: SM9CryptoData ← binary field
    CEREAL_SERIALIZE_BINARY_FIELD(ar, "dht_dynamic_challenges_r", r_);

    // blockCount_
    CEREAL_NVP_SERIALIZE(ar, "blockCount", blockCount_);

    // items_
    std::size_t itemCount = 0;
    CEREAL_NVP_SERIALIZE(ar, "itemCount", itemCount);
    items_.clear();
    items_.reserve(itemCount);
    for (std::size_t i = 0; i < itemCount; ++i) {
        ChallengeItem item;
        CEREAL_NVP_SERIALIZE(ar, "blockIndex", item.blockIndex);
        ar(cereal::binary_data(item.nu.data(), item.nu.size()));
        CEREAL_NVP_SERIALIZE(ar, "version", item.metadata.version);
        CEREAL_NVP_SERIALIZE(ar, "timestamp", item.metadata.timestamp);
        items_.push_back(std::move(item));
    }
}

} // namespace CAMatrix::Audit::Strategies::DHTDynamic
