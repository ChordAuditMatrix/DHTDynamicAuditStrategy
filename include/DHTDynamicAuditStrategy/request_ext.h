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
 * @file request_ext.h
 * @brief DHTDynamic audit request and result extension structures
 * @details Defines extension parameters for each stage of DHTDynamic audit.
 *          DHTDynamic uses BLS-based key generation (no KGC), so the extension
 *          structures differ from SM9Static:
 *          - No master key or user identity (BLS is identity-free)
 *          - Key generation uses random seed instead of KGC parameters
 *          - Tag generation includes fileId and user params directly
 *          - Proof generation includes tags and block source
 *          - Verification includes fileId and user public params
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-06
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef CAMATRIX_DHT_DYNAMIC_REQUEST_EXT_H
#define CAMATRIX_DHT_DYNAMIC_REQUEST_EXT_H

#include "DHTDynamicAuditStrategy/params.h"
#include "ChordAuditMatrixLib/interfaces/audit/data/audit_block_source.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/request_result.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/tags.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace CAMatrix::Audit::Strategies::DHTDynamic {

using AuditBlockSource = ::CAMatrix::Audit::Data::AuditBlockSource;

// ========== Algorithm Initialization ==========

/**
 * @struct DHTDynamicAlgoInitRequestExt
 * @brief DHTDynamic algorithm initialization request extension
 * @details DHTDynamic has no KGC, so algorithm initialization is a no-op.
 *          This struct exists to satisfy the StageExtBase interface.
 */
struct DHTDynamicAlgoInitRequestExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    DHTDynamicAlgoInitRequestExt() = default;
};

/**
 * @struct DHTDynamicAlgoInitResultExt
 * @brief DHTDynamic algorithm initialization result extension
 */
struct DHTDynamicAlgoInitResultExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    DHTDynamicAlgoInitResultExt() = default;
};

// ========== Key Generation ==========

/**
 * @struct DHTDynamicKeyGenRequestExt
 * @brief DHTDynamic key generation request extension
 * @details Contains optional seed for deterministic key generation.
 *          If seed is not provided, random keys are generated.
 */
struct DHTDynamicKeyGenRequestExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    /** @brief Optional RNG seed for deterministic key generation */
    std::optional<std::uint64_t> seed;

    DHTDynamicKeyGenRequestExt() = default;
};

/**
 * @struct DHTDynamicKeyGenResultExt
 * @brief DHTDynamic key generation result extension
 */
struct DHTDynamicKeyGenResultExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    DHTDynamicKeyGenResultExt() = default;
};

// ========== Tag Generation ==========

/**
 * @struct DHTDynamicTagsGenRequestExt
 * @brief DHTDynamic tag generation request extension
 * @details Contains fileId and user parameters needed for computing
 *          BLS signatures: σ_i = [sk]·curveHash(fileId‖i)
 */
struct DHTDynamicTagsGenRequestExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    /** @brief File identifier */
    std::string fileId;
    /** @brief User public parameters (pk, g, y, u) */
    std::shared_ptr<DHTDynamicPublicParams> userPublicParams;
    /** @brief User private parameters (sk, a) */
    std::shared_ptr<DHTDynamicPrivateParams> userPrivateParams;

    DHTDynamicTagsGenRequestExt() = default;
};

/**
 * @struct DHTDynamicTagsGenResultExt
 * @brief DHTDynamic tag generation result extension
 */
struct DHTDynamicTagsGenResultExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    DHTDynamicTagsGenResultExt() = default;
};

// ========== Challenge Generation ==========

/**
 * @struct DHTDynamicChallengeRequestExt
 * @brief DHTDynamic challenge generation request extension
 * @details Contains parameters for selecting random blocks and generating
 *          challenge coefficients with blind commitment R = [r]·y.
 *          Requires fileId to query stateStore for block metadata,
 *          and userPublicParams for the y point to compute R.
 */
struct DHTDynamicChallengeRequestExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    /** @brief File identifier (for querying stateStore block metadata) */
    std::string fileId;
    /** @brief User public parameters (contains y for computing R = [r]·y) */
    std::shared_ptr<DHTDynamicPublicParams> userPublicParams;
    /** @brief Total number of blocks in the file */
    std::size_t blockCount = 0;
    /** @brief Number of blocks to challenge */
    std::size_t challengeCount = 0;
    /** @brief Use pseudo-random selection if true */
    bool usePseudoRandom = true;
    /** @brief Optional RNG seed (only valid if usePseudoRandom is true) */
    std::optional<std::uint64_t> seed;

    DHTDynamicChallengeRequestExt() = default;
};

/**
 * @struct DHTDynamicChallengeResultExt
 * @brief DHTDynamic challenge generation result extension
 */
struct DHTDynamicChallengeResultExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    DHTDynamicChallengeResultExt() = default;
};

// ========== Proof Generation ==========

/**
 * @struct DHTDynamicProveRequestExt
 * @brief DHTDynamic proof generation request extension
 * @details Contains tags, block data, and user public parameters needed
 *          for computing the BLS aggregate proof (Θ, Λ).
 */
struct DHTDynamicProveRequestExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    /** @brief Tag collection */
    std::shared_ptr<::CAMatrix::Audit::Messages::Tags> tags;
    /** @brief Audit block source */
    std::shared_ptr<AuditBlockSource> blocks;
    /** @brief User public parameters (pk, g, y, u) */
    std::shared_ptr<DHTDynamicPublicParams> userPublicParams;

    DHTDynamicProveRequestExt() = default;
};

/**
 * @struct DHTDynamicProveResultExt
 * @brief DHTDynamic proof generation result extension
 */
struct DHTDynamicProveResultExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    DHTDynamicProveResultExt() = default;
};

// ========== Proof Verification ==========

/**
 * @struct DHTDynamicVerifyRequestExt
 * @brief DHTDynamic verification request extension
 * @details Contains fileId and user public parameters needed for
 *          verifying the aggregate proof Θ^r == Λ·e(H, R).
 *
 *          Note: The verifier does NOT hold individual tags (σ_j).
 *          Tags are held by the prover (storage node). The verifier
 *          only checks the aggregate proof equation.
 */
struct DHTDynamicVerifyRequestExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    /** @brief File identifier */
    std::string fileId;
    /** @brief User public parameters (pk, g, y, u) */
    std::shared_ptr<DHTDynamicPublicParams> userPublicParams;

    DHTDynamicVerifyRequestExt() = default;
};

/**
 * @struct DHTDynamicVerifyResultExt
 * @brief DHTDynamic verification result extension
 */
struct DHTDynamicVerifyResultExt final : public ::CAMatrix::Audit::Messages::StageExtBase {
    DHTDynamicVerifyResultExt() = default;
};

} // namespace CAMatrix::Audit::Strategies::DHTDynamic

#endif // CAMATRIX_DHT_DYNAMIC_REQUEST_EXT_H
