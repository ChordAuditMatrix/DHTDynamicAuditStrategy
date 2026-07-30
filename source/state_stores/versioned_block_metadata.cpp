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
 * @file versioned_block_metadata.cpp
 * @brief VersionedBlockMetadata serialization implementation
 * @details Serializes version and timestamp using cereal BinaryArchive.
 *          Format: [version: uint64][timestamp: uint64]
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-10
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/state_stores/versioned_block_metadata.h"

#include <cereal/archives/binary.hpp>

namespace CAMatrix::Audit::Core {

void VersionedBlockMetadata::do_serialize(cereal::BinaryOutputArchive& ar) const
{
    CEREAL_NVP_SERIALIZE(ar, "version", version);
    CEREAL_NVP_SERIALIZE(ar, "timestamp", timestamp);
}

void VersionedBlockMetadata::do_deserialize(cereal::BinaryInputArchive& ar)
{
    CEREAL_NVP_SERIALIZE(ar, "version", version);
    CEREAL_NVP_SERIALIZE(ar, "timestamp", timestamp);
}

} // namespace CAMatrix::Audit::Core
