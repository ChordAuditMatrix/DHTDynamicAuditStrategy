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
 * @file tags.cpp
 * @brief DHTDynamic audit tag implementation
 * @details Implements DHTDynamicTag construction, Tag interface operations
 *          (assign, +, -, ==, *), and cereal serialization.
 *
 *          Tag operations use G1 point arithmetic:
 *          - Addition: σ₁ + σ₂ (point addition on G1)
 *          - Subtraction: σ₁ - σ₂ (point subtraction on G1)
 *          - Scalar multiplication: [k]·σ (scalar-point multiplication)
 *          - Equality: G1 point comparison
 *
 *          Serialization format:
 *          - sigma_: CEREAL_SERIALIZE_RAW_FIELD (SM9_Z256_POINT)
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-08
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/tags.h"

#include "ChordAuditMatrixLib/implementations/crypto/sm9/points.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/data.h"
#include "ChordAuditMatrixLib/interfaces/crypto/serializable.h"

#include <cereal/archives/binary.hpp>

#include <stdexcept>

namespace CAMatrix::Audit::Strategies::DHTDynamic {

// ─────────────────────────────────────────────────────────────────────────────
// Construction / Destruction
// ─────────────────────────────────────────────────────────────────────────────

DHTDynamicTag::DHTDynamicTag()
    : sigma_()
{
    sigma_.setInfinity();
}

DHTDynamicTag::DHTDynamicTag(const CAMatrix::Crypto::SM9BLS::G1Point& sigma)
    : sigma_(sigma)
{
}

DHTDynamicTag::~DHTDynamicTag() = default;

// ─────────────────────────────────────────────────────────────────────────────
// Tag interface overrides
// ─────────────────────────────────────────────────────────────────────────────

void DHTDynamicTag::assign(const CAMatrix::Audit::Messages::Tag& other)
{
    const auto* typed = dynamic_cast<const DHTDynamicTag*>(&other);
    if (!typed) {
        throw std::runtime_error("DHTDynamicTag assign type mismatch");
    }
    sigma_ = typed->sigma_;
}

std::shared_ptr<CAMatrix::Audit::Messages::Tag> DHTDynamicTag::operator+(
    const CAMatrix::Audit::Messages::Tag& other) const
{
    const auto* typed = dynamic_cast<const DHTDynamicTag*>(&other);
    if (!typed) {
        throw std::runtime_error("DHTDynamicTag add type mismatch");
    }
    // G1 point addition: σ₁ + σ₂
    auto sumPtr = sigma_ + typed->sigma_;
    auto sumG1 = std::static_pointer_cast<CAMatrix::Crypto::SM9BLS::G1Point>(sumPtr);
    return std::make_shared<DHTDynamicTag>(*sumG1);
}

std::shared_ptr<CAMatrix::Audit::Messages::Tag> DHTDynamicTag::operator-(
    const CAMatrix::Audit::Messages::Tag& other) const
{
    const auto* typed = dynamic_cast<const DHTDynamicTag*>(&other);
    if (!typed) {
        throw std::runtime_error("DHTDynamicTag sub type mismatch");
    }
    // G1 point subtraction: σ₁ - σ₂
    auto diffPtr = sigma_ - typed->sigma_;
    auto diffG1 = std::static_pointer_cast<CAMatrix::Crypto::SM9BLS::G1Point>(diffPtr);
    return std::make_shared<DHTDynamicTag>(*diffG1);
}

bool DHTDynamicTag::operator==(const CAMatrix::Audit::Messages::Tag& other) const
{
    const auto* typed = dynamic_cast<const DHTDynamicTag*>(&other);
    if (!typed) {
        return false;
    }
    return sigma_ == typed->sigma_;
}

std::shared_ptr<CAMatrix::Audit::Messages::Tag> DHTDynamicTag::operator*(
    const CAMatrix::Crypto::CryptoDataBase& scalar) const
{
    // Cast to SM9CryptoData for scalar multiplication
    const auto* sm9Scalar = dynamic_cast<const CAMatrix::Crypto::SM9BLS::SM9CryptoData*>(&scalar);
    if (!sm9Scalar) {
        throw std::runtime_error("DHTDynamicTag scalar multiplication requires SM9CryptoData");
    }
    // [k]·σ — scalar-point multiplication on G1
    auto weightedPtr = sigma_ * (*sm9Scalar);
    auto weighted = std::static_pointer_cast<CAMatrix::Crypto::SM9BLS::G1Point>(weightedPtr);
    return std::make_shared<DHTDynamicTag>(*weighted);
}

// ─────────────────────────────────────────────────────────────────────────────
// Serialization
// ─────────────────────────────────────────────────────────────────────────────

void DHTDynamicTag::do_serialize(cereal::BinaryOutputArchive& ar) const
{
    // sigma_: G1Point → raw struct
    auto sigmaRaw = sigma_.toRawStruct();
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_tag_sigma", sigmaRaw);
}

void DHTDynamicTag::do_deserialize(cereal::BinaryInputArchive& ar)
{
    // sigma_: G1Point ← raw struct
    SM9_Z256_POINT sigmaRaw{};
    CEREAL_SERIALIZE_RAW_FIELD(ar, "dht_dynamic_tag_sigma", sigmaRaw);
    sigma_ = CAMatrix::Crypto::SM9BLS::G1Point(&sigmaRaw);
}

} // namespace CAMatrix::Audit::Strategies::DHTDynamic
