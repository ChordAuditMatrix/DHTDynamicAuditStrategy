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
 * @file tags.h
 * @brief DHTDynamic audit tag type
 * @details Defines DHTDynamicTag, the concrete Tag implementation for the
 *          DHT-based dynamic PDP scheme. Each tag consists of:
 *          - sigma_: A G1 point (SM9+BLS hybrid signature on the block)
 *
 *          BlockMetadata (version, timestamp) is stored separately in
 *          DynamicPdpStateStore, NOT in the tag. Challenge generation
 *          retrieves metadata from stateStore, not from tags.
 *
 *          Tag operations:
 *          - Addition: Point addition on G1 (σ₁ + σ₂)
 *          - Subtraction: Point subtraction on G1 (σ₁ - σ₂)
 *          - Scalar multiplication: [k]·σ on G1
 *          - Equality: G1 point comparison
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-08
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef CAMATRIX_DHT_DYNAMIC_TAGS_H
#define CAMATRIX_DHT_DYNAMIC_TAGS_H

#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/points.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/tag.h"
#include "ChordAuditMatrixLib/interfaces/crypto/serializable.h"

#include <memory>

namespace CAMatrix::Audit::Strategies::DHTDynamic {

/**
 * @class DHTDynamicTag
 * @brief Tag type for DHTDynamic audit (BLS signature on G1)
 * @details Each DHTDynamicTag contains only:
 *          - sigma_: BLS signature point on G1 curve, computed as [a]·[H₁(fileId‖i) + m_i·u]
 *            where a = BLS signing scalar, H₁ = hashToCurve, m_i = hashToScalar(block_i), u = proof binding point
 *
 *          BlockMetadata (version, timestamp) is NOT stored in the tag.
 *          It is managed separately by DynamicPdpStateStore.
 *
 *          Supports Tag interface operations via G1 point arithmetic.
 */
class DHTDynamicTag final : public ::CAMatrix::Audit::Messages::Tag {
public:
    DHTDynamicTag();
    explicit DHTDynamicTag(const ::CAMatrix::Crypto::SM9BLS::G1Point& sigma);
    ~DHTDynamicTag() override;

    // ── Tag interface overrides ──

    /**
     * @brief Assign from another tag
     * @param other [IN] Source tag to copy
     */
    void assign(const ::CAMatrix::Audit::Messages::Tag& other) override;

    /**
     * @brief Point addition: this + other
     * @param other [IN] Tag to add
     * @return shared_ptr<Tag>, Result of G1 point addition
     */
    std::shared_ptr<::CAMatrix::Audit::Messages::Tag> operator+(
        const ::CAMatrix::Audit::Messages::Tag& other) const override;

    /**
     * @brief Point subtraction: this - other
     * @param other [IN] Tag to subtract
     * @return shared_ptr<Tag>, Result of G1 point subtraction
     */
    std::shared_ptr<::CAMatrix::Audit::Messages::Tag> operator-(
        const ::CAMatrix::Audit::Messages::Tag& other) const override;

    /**
     * @brief Equality comparison
     * @param other [IN] Tag to compare against
     * @return bool, True if G1 points are equal
     */
    bool operator==(const ::CAMatrix::Audit::Messages::Tag& other) const override;

    /**
     * @brief Scalar multiplication: [scalar]·this
     * @param scalar [IN] Scalar multiplier
     * @return shared_ptr<Tag>, Result of scalar multiplication
     */
    std::shared_ptr<::CAMatrix::Audit::Messages::Tag> operator*(
        const ::CAMatrix::Crypto::CryptoDataBase& scalar) const override;

    // ── DHTDynamic-specific accessors ──

    /**
     * @brief Get the BLS signature point
     * @return const G1Point&, Sigma (σ) point on G1
     */
    const ::CAMatrix::Crypto::SM9BLS::G1Point& sigma() const noexcept { return sigma_; }

    /**
     * @brief Set the BLS signature point
     * @param sigma [IN] New sigma point
     */
    void setSigma(const ::CAMatrix::Crypto::SM9BLS::G1Point& sigma) { sigma_ = sigma; }

protected:
    /**
     * @brief Serialize tag to binary archive
     * @param ar [OUT] cereal BinaryOutputArchive
     */
    void do_serialize(cereal::BinaryOutputArchive& ar) const override;

    /**
     * @brief Deserialize tag from binary archive
     * @param ar [IN] cereal BinaryInputArchive
     */
    void do_deserialize(cereal::BinaryInputArchive& ar) override;

private:
    /** @brief BLS signature point: σ = [a]·[H₁(fileId‖i) + m_i·u] */
    ::CAMatrix::Crypto::SM9BLS::G1Point sigma_;
};

} // namespace CAMatrix::Audit::Strategies::DHTDynamic

#endif // CAMATRIX_DHT_DYNAMIC_TAGS_H
