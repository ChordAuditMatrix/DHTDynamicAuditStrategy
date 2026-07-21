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
 * @file params.h
 * @brief DHTDynamic algorithm and user parameter types
 * @details Defines the parameter classes for the DHT-based dynamic PDP scheme:
 *          - DHTDynamicAlgoPublicParams: Empty algorithm-level public params (no KGC)
 *          - DHTDynamicAlgoPrivateParams: Empty algorithm-level private params (no KGC)
 *          - DHTDynamicPublicParams: User-level public params (pk, g, y, u)
 *          - DHTDynamicPrivateParams: User-level private params (sk, a)
 *
 *          Key generation is per-user in DHTDynamic (no KGC/master key).
 *          The algorithm-level params are empty stubs to satisfy the
 *          AuditStrategy interface contract.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-06
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef CAMATRIX_DHT_DYNAMIC_PARAMS_H
#define CAMATRIX_DHT_DYNAMIC_PARAMS_H

#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/data.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/points.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/algorithm_params.h"
#include "ChordAuditMatrixLib/interfaces/crypto/serializable.h"

namespace CAMatrix::Audit::Strategies::DHTDynamic {

// ── Algorithm-level params (empty stubs — no KGC in DHTDynamic) ──

/**
 * @class DHTDynamicAlgoPublicParams
 * @brief Empty algorithm-level public params for DHTDynamic
 * @details DHTDynamic has no KGC; algorithm-level params are unused.
 *          This class exists to satisfy the AuditStrategy interface contract.
 */
class DHTDynamicAlgoPublicParams final : public ::CAMatrix::Audit::Messages::AlgoPublicParams {
public:
    /**
     * @brief Serialize empty algo public params
     * @param ar [OUT] cereal BinaryOutputArchive (no-op)
     */
    void do_serialize(cereal::BinaryOutputArchive& ar) const override {}

    /**
     * @brief Deserialize empty algo public params
     * @param ar [IN] cereal BinaryInputArchive (no-op)
     */
    void do_deserialize(cereal::BinaryInputArchive& ar) override {}
};

/**
 * @class DHTDynamicAlgoPrivateParams
 * @brief Empty algorithm-level private params for DHTDynamic
 * @details DHTDynamic has no KGC; algorithm-level params are unused.
 *          This class exists to satisfy the AuditStrategy interface contract.
 */
class DHTDynamicAlgoPrivateParams final : public ::CAMatrix::Audit::Messages::AlgoPrivateParams {
public:
    /**
     * @brief Serialize empty algo private params
     * @param ar [OUT] cereal BinaryOutputArchive (no-op)
     */
    void do_serialize(cereal::BinaryOutputArchive& ar) const override {}

    /**
     * @brief Deserialize empty algo private params
     * @param ar [IN] cereal BinaryInputArchive (no-op)
     */
    void do_deserialize(cereal::BinaryInputArchive& ar) override {}
};

// ── User-level params ──

/**
 * @class DHTDynamicPublicParams
 * @brief User-level public parameters for DHTDynamic
 * @details Contains the BLS verification key material:
 *          - pk: System public key = [sk]·P₂
 *          - g:  Generator commitment = [r]·P₂
 *          - y:  Signing commitment = [a]·g
 *          - u:  Proof binding point = [r']·P₁
 */
class DHTDynamicPublicParams final : public ::CAMatrix::Audit::Messages::AlgoPublicParams {
public:
    /** @brief System public key: pk = [sk]·P₂ */
    ::CAMatrix::Crypto::SM9BLS::G2Point pk;
    /** @brief Generator commitment: g = [r]·P₂ */
    ::CAMatrix::Crypto::SM9BLS::G2Point g;
    /** @brief Signing commitment: y = [a]·g */
    ::CAMatrix::Crypto::SM9BLS::G2Point y;
    /** @brief Proof binding point: u = [r']·P₁ */
    ::CAMatrix::Crypto::SM9BLS::G1Point u;

    /**
     * @brief Serialize user public params to binary archive
     * @param ar [OUT] cereal BinaryOutputArchive
     */
    void do_serialize(cereal::BinaryOutputArchive& ar) const override;

    /**
     * @brief Deserialize user public params from binary archive
     * @param ar [IN] cereal BinaryInputArchive
     */
    void do_deserialize(cereal::BinaryInputArchive& ar) override;
};

/**
 * @class DHTDynamicPrivateParams
 * @brief User-level private parameters for DHTDynamic
 * @details Contains the BLS signing key material:
 *          - sk: SM9 signing key (used for file ID signature)
 *          - a:  BLS signing scalar (used in σ = [a]·[H₁(fileId‖i) + m_i·u])
 */
class DHTDynamicPrivateParams final : public ::CAMatrix::Audit::Messages::AlgoPrivateParams {
public:
    /** @brief SM9 signing key scalar (for file ID signature) */
    ::CAMatrix::Crypto::SM9BLS::SM9CryptoData sk;
    /** @brief BLS signing scalar (for block tag: σ = [a]·[H₁(fileId‖i) + m_i·u]) */
    ::CAMatrix::Crypto::SM9BLS::SM9CryptoData a;

    /**
     * @brief Serialize user private params to binary archive
     * @param ar [OUT] cereal BinaryOutputArchive
     */
    void do_serialize(cereal::BinaryOutputArchive& ar) const override;

    /**
     * @brief Deserialize user private params from binary archive
     * @param ar [IN] cereal BinaryInputArchive
     */
    void do_deserialize(cereal::BinaryInputArchive& ar) override;
};

} // namespace CAMatrix::Audit::Strategies::DHTDynamic

#endif // CAMATRIX_DHT_DYNAMIC_PARAMS_H
