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
 * @file params.cpp
 * @brief DHTDynamic parameter serialization implementation
 * @details Serializes DHTDynamicPublicParams (G2Point pk/g/y, G1Point u) and
 *          DHTDynamicPrivateParams (SM9CryptoData sk/a) using cereal BinaryArchive.
 *
 *          G2Point fields use CEREAL_SERIALIZE_RAW_FIELD with SM9_Z256_TWIST_POINT.
 *          G1Point fields use CEREAL_SERIALIZE_RAW_FIELD with SM9_Z256_POINT.
 *          SM9CryptoData fields use CEREAL_SERIALIZE_BINARY_FIELD.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-08
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/params.h"

#include <cereal/archives/binary.hpp>

#include "ChordAuditMatrixLib/implementations/crypto/sm9/points.h"
#include "ChordAuditMatrixLib/interfaces/crypto/serializable.h"

namespace CAMatrix::Audit::Strategies::DHTDynamic {

// ─────────────────────────────────────────────────────────────────────────────
// DHTDynamicPublicParams serialization
// ─────────────────────────────────────────────────────────────────────────────

void DHTDynamicPublicParams::do_serialize(cereal::BinaryOutputArchive& ar) const
{
    // G2Point pk → raw struct
    auto pkRaw = pk.toRawStruct();
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_public_params_pk", pkRaw);

    // G2Point g → raw struct
    auto gRaw = g.toRawStruct();
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_public_params_g", gRaw);

    // G2Point y → raw struct
    auto yRaw = y.toRawStruct();
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_public_params_y", yRaw);

    // G1Point u → raw struct
    auto uRaw = u.toRawStruct();
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_public_params_u", uRaw);
}

void DHTDynamicPublicParams::do_deserialize(cereal::BinaryInputArchive& ar)
{
    // G2Point pk ← raw struct
    SM9_Z256_TWIST_POINT pkRaw{};
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_public_params_pk", pkRaw);
    pk = CAMatrix::Crypto::SM9BLS::G2Point(&pkRaw);

    // G2Point g ← raw struct
    SM9_Z256_TWIST_POINT gRaw{};
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_public_params_g", gRaw);
    g = CAMatrix::Crypto::SM9BLS::G2Point(&gRaw);

    // G2Point y ← raw struct
    SM9_Z256_TWIST_POINT yRaw{};
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_public_params_y", yRaw);
    y = CAMatrix::Crypto::SM9BLS::G2Point(&yRaw);

    // G1Point u ← raw struct
    SM9_Z256_POINT uRaw{};
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_public_params_u", uRaw);
    u = CAMatrix::Crypto::SM9BLS::G1Point(&uRaw);
}

// ─────────────────────────────────────────────────────────────────────────────
// DHTDynamicPrivateParams serialization
// ─────────────────────────────────────────────────────────────────────────────

void DHTDynamicPrivateParams::do_serialize(cereal::BinaryOutputArchive& ar) const
{
    CEREAL_SERIALIZE_BINARY_FIELD(ar, "dht_dynamic_private_params_sk", sk);
    CEREAL_SERIALIZE_BINARY_FIELD(ar, "dht_dynamic_private_params_a", a);
}

void DHTDynamicPrivateParams::do_deserialize(cereal::BinaryInputArchive& ar)
{
    CEREAL_SERIALIZE_BINARY_FIELD(ar, "dht_dynamic_private_params_sk", sk);
    CEREAL_SERIALIZE_BINARY_FIELD(ar, "dht_dynamic_private_params_a", a);
}

} // namespace CAMatrix::Audit::Strategies::DHTDynamic
