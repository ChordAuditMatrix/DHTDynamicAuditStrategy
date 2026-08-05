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
 * @file proves.cpp
 * @brief DHTDynamic audit proof serialization implementation
 * @details Serializes DHTDynamicProves using cereal BinaryArchive.
 *          Format:
 *          - theta_: SM9GTElement serialized as binary blob
 *          - lambda_: SM9GTElement serialized as binary blob
 *
 *          Since SM9GTElement inherits CryptoSerializable with its own
 *          do_serialize/do_deserialize, we use serialize()/deserialize()
 *          to obtain/reconstruct the byte representation.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-08
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/proves.h"

#include "ChordAuditMatrixLib/interfaces/crypto/serializable.h"

#include <cereal/archives/binary.hpp>

#include <stdexcept>

namespace CAMatrix::Audit::Strategies::DHTDynamic {

DHTDynamicProves::~DHTDynamicProves() = default;

void DHTDynamicProves::do_serialize(cereal::BinaryOutputArchive& ar) const
{
    // theta_: SM9GTElement → CryptoArray (std::vector<uint8_t>) via serialize()
    auto thetaData = theta_.serialize();
    CEREAL_NVP_SERIALIZE(ar, "dht_dynamic_proves_theta", thetaData);

    // lambda_: SM9GTElement → CryptoArray (std::vector<uint8_t>) via serialize()
    auto lambdaData = lambda_.serialize();
    CEREAL_NVP_SERIALIZE(ar, "dht_dynamic_proves_lambda", lambdaData);
}

void DHTDynamicProves::do_deserialize(cereal::BinaryInputArchive& ar)
{
    // theta_: SM9GTElement ← CryptoArray via deserialize()
    // CEREAL_NVP_SERIALIZE handles vector size automatically (unlike
    // CEREAL_SERIALIZE_BINARY_FIELD which requires pre-sized buffer).
    CAMatrix::Crypto::CryptoArray thetaData;
    CEREAL_NVP_SERIALIZE(ar, "dht_dynamic_proves_theta", thetaData);
    if (!theta_.deserialize(thetaData)) {
        throw std::runtime_error("DHTDynamicProves: failed to deserialize theta");
    }

    // lambda_: SM9GTElement ← CryptoArray via deserialize()
    CAMatrix::Crypto::CryptoArray lambdaData;
    CEREAL_NVP_SERIALIZE(ar, "dht_dynamic_proves_lambda", lambdaData);
    if (!lambda_.deserialize(lambdaData)) {
        throw std::runtime_error("DHTDynamicProves: failed to deserialize lambda");
    }
}

} // namespace CAMatrix::Audit::Strategies::DHTDynamic
