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
 * @file versioned_block_metadata.h
 * @brief Default BlockMetadata implementation with version and timestamp
 * @details VersionedBlockMetadata is the default concrete BlockMetadata subclass
 *          for dynamic PDP schemes. It tracks per-block version and timestamp,
 *          which are used in:
 *          - Tag generation: W_i = hashBlock(serialized metadata)
 *          - Challenge generation: metadata included in challenge items
 *          - Maintenance: version incremented on update, timestamp refreshed
 *
 *          Algorithms that need metadata as hash input simply call the
 *          serialization method and use the serialized data as input.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-10
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef DHTDYNAMIC_VERSIONED_BLOCK_METADATA_H
#define DHTDYNAMIC_VERSIONED_BLOCK_METADATA_H

#include "ChordAuditMatrixLib/interfaces/audit/state_stores/block_metadata.h"

#include <chrono>
#include <cstdint>
#include <memory>

namespace CAMatrix::Audit::Core {

/**
 * @class VersionedBlockMetadata
 * @brief Default per-block metadata with version and timestamp
 * @details Tracks version and timestamp for each block. Version is incremented
 *          on each update operation; timestamp records the last modification time.
 *          Both fields are serialized and used as hash input for tag generation.
 */
class VersionedBlockMetadata final : public BlockMetadata {
public:
    /**
     * @brief Default constructor — version=1, timestamp=0
     */
    VersionedBlockMetadata() = default;

    /**
     * @brief Construct with explicit version and timestamp
     * @param ver [IN] Block version number
     * @param ts [IN] Last modification timestamp (epoch seconds)
     */
    VersionedBlockMetadata(std::uint64_t ver, std::uint64_t ts)
        : version(ver), timestamp(ts) {}

    /**
     * @brief Deep copy this metadata
     * @return unique_ptr<BlockMetadata>, Cloned instance
     */
    std::unique_ptr<BlockMetadata> clone() const override {
        return std::make_unique<VersionedBlockMetadata>(version, timestamp);
    }

    /**
     * @brief Equality comparison
     * @param other [IN] Metadata to compare against
     * @return bool, True if version and timestamp are equal
     */
    bool operator==(const VersionedBlockMetadata& other) const noexcept {
        return version == other.version && timestamp == other.timestamp;
    }

    /**
     * @brief Increment version and refresh timestamp
     * @details Called by DynamicPdpStateStore::modifyBlock() to update metadata
     *          in-place without requiring the caller to construct a new object
     */
    void bump() override {
        ++version;
        timestamp = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
    }

    // ── CryptoSerializable overrides ──

    /**
     * @brief Serialize metadata to binary archive
     * @param ar [OUT] cereal BinaryOutputArchive
     */
    void do_serialize(cereal::BinaryOutputArchive& ar) const override;

    /**
     * @brief Deserialize metadata from binary archive
     * @param ar [IN] cereal BinaryInputArchive
     */
    void do_deserialize(cereal::BinaryInputArchive& ar) override;

    // ── Data members ──

    std::uint64_t version = 1;    ///< Block version (incremented on update)
    std::uint64_t timestamp = 0;  ///< Last modification timestamp (epoch seconds)
};

} // namespace CAMatrix::Audit::Core

#endif // DHTDYNAMIC_VERSIONED_BLOCK_METADATA_H
