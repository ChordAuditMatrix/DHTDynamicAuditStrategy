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
 * @file proves.h
 * @brief DHTDynamic audit proof types
 * @details Defines DHTDynamicProves, the concrete Proves implementation for the
 *          DHT-based dynamic PDP scheme. The proof consists of two GT elements:
 *          - theta_: Θ = ∏ e(σ_{i_j}, g)^{ν_j} (aggregated weighted pairing)
 *          - lambda_: Λ = e(u, R)^{M} where M = Σ(ν_j · m_{i_j})
 *
 *          Verification equation (aggregate):
 *            Θ^r == Λ · e(H, R)
 *            where H = Σ(ν_j · H₁(fileId‖i_j)) ∈ G₁, R = [r]·y ∈ G₂
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-06
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef CAMATRIX_DHT_DYNAMIC_PROVES_H
#define CAMATRIX_DHT_DYNAMIC_PROVES_H

#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/gt_element.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/proves.h"

#include <memory>

namespace CAMatrix::Audit::Strategies::DHTDynamic {

/**
 * @class DHTDynamicProves
 * @brief Proof container for DHTDynamic audit
 * @details Contains the BLS aggregate proof tuple (Θ, Λ):
 *          - theta_: Θ = ∏ e(σ_{i_j}, g)^{ν_j}
 *            Aggregated weighted pairing of tags with generator commitment g
 *          - lambda_: Λ = e(u, R)^{M} where M = Σ(ν_j · m_{i_j})
 *            Pairing of proof binding point u with blind commitment R,
 *            raised to the power of the weighted block metadata sum
 *
 *          Verification: Θ^r == Λ · e(H, R) where H = Σ(ν_j · H₁(fileId‖i_j))
 */
class DHTDynamicProves final : public ::CAMatrix::Audit::Messages::Proves {
public:
    DHTDynamicProves() = default;
    ~DHTDynamicProves() override;

    // ── Accessors ──

    /**
     * @brief Get the aggregated weighted pairing Θ
     * @return const SM9GTElement&, Theta element
     */
    const ::CAMatrix::Crypto::SM9BLS::SM9GTElement& theta() const noexcept { return theta_; }

    /**
     * @brief Set the aggregated weighted pairing Θ
     * @param theta [IN] New theta element
     */
    void setTheta(const ::CAMatrix::Crypto::SM9BLS::SM9GTElement& theta) { theta_ = theta; }

    /**
     * @brief Get the proof binding pairing Λ
     * @return const SM9GTElement&, Lambda element
     */
    const ::CAMatrix::Crypto::SM9BLS::SM9GTElement& lambda() const noexcept { return lambda_; }

    /**
     * @brief Set the proof binding pairing Λ
     * @param lambda [IN] New lambda element
     */
    void setLambda(const ::CAMatrix::Crypto::SM9BLS::SM9GTElement& lambda) { lambda_ = lambda; }

protected:
    /**
     * @brief Serialize proof to binary archive
     * @param ar [OUT] cereal BinaryOutputArchive
     */
    void do_serialize(cereal::BinaryOutputArchive& ar) const override;

    /**
     * @brief Deserialize proof from binary archive
     * @param ar [IN] cereal BinaryInputArchive
     */
    void do_deserialize(cereal::BinaryInputArchive& ar) override;

private:
    /** @brief Aggregated weighted pairing: Θ = ∏ e(σ_{i_j}, g)^{ν_j} */
    ::CAMatrix::Crypto::SM9BLS::SM9GTElement theta_;

    /** @brief Proof binding pairing: Λ = e(u, R)^{M} */
    ::CAMatrix::Crypto::SM9BLS::SM9GTElement lambda_;
};

} // namespace CAMatrix::Audit::Strategies::DHTDynamic

#endif // CAMATRIX_DHT_DYNAMIC_PROVES_H
