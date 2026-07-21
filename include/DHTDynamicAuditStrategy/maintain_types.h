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
 * @file maintain_types.h
 * @brief DHTDynamic maintenance operation extension types
 * @details Defines the DHTDynamicMaintainExt structure used in maintenance
 *          operations for the DHT-based dynamic PDP scheme. This extension
 *          carries the file identifier, operation type, and affected block
 *          indices needed to update the DHT state store.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-06
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef CAMATRIX_DHT_DYNAMIC_MAINTAIN_TYPES_H
#define CAMATRIX_DHT_DYNAMIC_MAINTAIN_TYPES_H

#include "ChordAuditMatrixLib/interfaces/audit/messages/request_result.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace CAMatrix::Audit::Strategies::DHTDynamic {

/**
 * @struct DHTDynamicMaintainExt
 * @brief Extension data for DHTDynamic maintenance operations
 * @details Carries the file identifier, operation type, and block indices
 *          needed to update the DHT state store during maintenance.
 *
 *          maintenance() is responsible ONLY for StateStore updates
 *          (modifyBlock/insertBlock/deleteBlock). Tag management is the
 *          caller's responsibility — new tags are generated via generateTags()
 *          and sent to Storage for persistence; maintenance() does not
 *          touch the Tags collection at all.
 */
struct DHTDynamicMaintainExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    /** @brief File identifier to maintain */
    std::string fileId;

    /** @brief Type of maintenance operation (Update/Insert/Delete) */
    ::CAMatrix::Audit::Messages::MaintenanceOpType opType =
        ::CAMatrix::Audit::Messages::MaintenanceOpType::Update;

    /** @brief Block indices affected by this operation */
    std::vector<std::size_t> blockIndices;

    // ── CryptoSerializable overrides ──
    void do_serialize(cereal::BinaryOutputArchive& ar) const override {
        ar(fileId);
        ar(static_cast<std::uint8_t>(opType));
        ar(blockIndices);
    }

    void do_deserialize(cereal::BinaryInputArchive& ar) override {
        ar(fileId);
        std::uint8_t opVal;
        ar(opVal);
        opType = static_cast<::CAMatrix::Audit::Messages::MaintenanceOpType>(opVal);
        ar(blockIndices);
    }
};

} // namespace CAMatrix::Audit::Strategies::DHTDynamic

#endif // CAMATRIX_DHT_DYNAMIC_MAINTAIN_TYPES_H
