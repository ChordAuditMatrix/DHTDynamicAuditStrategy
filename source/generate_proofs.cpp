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
 * @file generate_proofs.cpp
 * @brief Implementation of proof generation and verification for DHTDynamic strategy
 * @details Uses the SM9+BLS hybrid scheme for dynamic PDP proof generation and verification.
 *
 *          Tag formula: σ_i = [a]·[H₁(fileId‖i) + m_i·u]
 *
 *          Proof generation (§6.6):
 *            For each challenged block index i_j:
 *              θ_{i_j} = e(σ_{i_j}, g)       — BLS pairing of tag with generator g
 *              Θ = Θ · θ_{i_j}^{ν_j}          — weighted product in GT
 *              M = M + ν_j · m_{i_j}           — weighted message sum in Z_p
 *            Λ = e(u, R)^M                      — binding pairing
 *            Returns DHTDynamicProves{theta=Θ, lambda=Λ}
 *
 *          Proof verification (§6.7):
 *            Compute H = Σ(ν_j · H₁(fileId‖i_j)) ∈ G₁
 *            Check: Θ^r == Λ · e(H, R)
 *
 *            Mathematical derivation:
 *              σ_i = [a]·[H_i + m_i·u]
 *              e(σ_i, g) = e(H_i + m_i·u, [a]·g) = e(H_i + m_i·u, y)
 *              Θ = ∏ e(σ_i, g)^{ν_j} = e(H + M·u, y)
 *              Θ^r = e(H + M·u, [r]·y) = e(H + M·u, R)
 *              Λ · e(H, R) = e(u, R)^M · e(H, R) = e(M·u + H, R)
 *              Therefore: Θ^r == Λ · e(H, R) ✓
 *
 * @author Dylan Liu
 * @version 1.1.0
 * @date 2026-07-09
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/strategy.h"
#include "DHTDynamicAuditStrategy/common.h"
#include "DHTDynamicAuditStrategy/state_stores/versioned_block_metadata.h"

#include <spdlog/spdlog.h>

namespace CAMatrix::Audit::Strategies {

using namespace DHTDynamic;

// ========================================================================
// Proof Generation
// ========================================================================

CAMatrix::Audit::Messages::GenerateProofsResult DHTDynamicAuditStrategy::generateProofs(
    const CAMatrix::Audit::Messages::GenerateProofsRequest& input)
{
    CAMatrix::Audit::Messages::GenerateProofsResult result;

    // ── Validate extension and challenges ──
    auto ext = std::dynamic_pointer_cast<DHTDynamicProveRequestExt>(input.ext);
    auto challenges = std::dynamic_pointer_cast<DHTDynamicChallenges>(input.challenges);
    if (!ext || !challenges || !ext->blocks || !ext->tags || !ext->userPublicParams) {
        spdlog::error("DHTDynamicAuditStrategy::generateProofs: missing ext/challenges/blocks/tags/userPublicParams");
        return result;
    }

    // Guard: empty challenge items
    if (challenges->items().empty()) {
        spdlog::warn("DHTDynamicAuditStrategy::generateProofs: no challenge items, "
                     "returning empty proof result");
        return result;
    }

    const G2Point& g = ext->userPublicParams->g;
    const G1Point& u = ext->userPublicParams->u;
    const G2Point& R = challenges->R();

    spdlog::debug("DHTDynamicAuditStrategy::generateProofs: challengeCount={} blockCount={}",
                 challenges->challengeCount(), challenges->blockCount());

    // ========== Step 1: Compute Θ = ∏ e(σ_{i_j}, g)^{ν_j} ==========
    // ========== Step 2: Compute M = Σ(ν_j · m_{i_j}) ==========
    SM9GTElement Theta;  // Θ — aggregated weighted pairing
    Theta.setOne();      // Initialize to multiplicative identity in GT

    SM9CryptoData M(uint64_t(0));  // M = sum of weighted block scalars (must be zero-initialized)
    bool accumulated = false;

    for (const auto& item : challenges->items()) {
        const std::size_t idx = item.blockIndex - 1;  // 1-based challenge → 0-based tags index
        if (item.blockIndex == 0 || !ext->tags->contains(idx)) {
            spdlog::warn("DHTDynamicAuditStrategy::generateProofs: skipping challenge item "
                         "with blockIndex={} (tags maxIndex={}) — {}",
                         item.blockIndex, ext->tags->maxIndex(),
                         item.blockIndex == 0 ? "zero index" : "out of range or not loaded");
            continue;
        }

        auto tag = std::dynamic_pointer_cast<DHTDynamicTag>(ext->tags->getByIndex(idx));
        if (!tag) {
            spdlog::warn("DHTDynamicAuditStrategy::generateProofs: tag at index {} is not DHTDynamicTag",
                         item.blockIndex);
            continue;
        }

        const G1Point& sigma = tag->sigma();

        // Guard: sigma must not be at infinity (would cause pairing failure)
        if (sigma.isInfinity()) {
            spdlog::warn("DHTDynamicAuditStrategy::generateProofs: sigma at blockIndex={} is at infinity, skipping",
                         item.blockIndex);
            continue;
        }

        // θ_{i_j} = e(σ_{i_j}, g) — pairing of tag with generator g
        SM9GTElement theta_ij;
        if (!theta_ij.pairing(sigma, g)) {
            spdlog::warn("DHTDynamicAuditStrategy::generateProofs: pairing failed for blockIndex={}",
                         item.blockIndex);
            continue;
        }

        // θ_{i_j}^{ν_j} — raise pairing result to challenge coefficient
        auto theta_nu = theta_ij ^ item.nu;  // returns shared_ptr<GTElement>
        if (!theta_nu) {
            spdlog::warn("DHTDynamicAuditStrategy::generateProofs: exponentiation failed for blockIndex={}",
                         item.blockIndex);
            continue;
        }

        // Θ = Θ · θ_{i_j}^{ν_j} — accumulate in GT
        auto newTheta = Theta * *theta_nu;  // returns shared_ptr<GTElement>
        if (newTheta) {
            Theta.assign(*newTheta);
        }

        // M += ν_j · Σ segment_j — accumulate weighted block scalar
        // Each block is split into 32-byte segments; the scalar sum Σ segment_j
        // is computed by accumulateBlockSegmentsScalar, then weighted by ν_j.
        // This prevents the CSP from caching only a hash digest to pass audit.
        const std::vector<std::uint8_t> block = ext->blocks->block(idx);
        const SM9CryptoData blockScalar = DHTDynamic::accumulateBlockSegmentsScalar(block);
        auto nu_m = item.nu * blockScalar;  // returns CryptoDataPtr
        if (nu_m) {
            M.assign(*(M + *nu_m));
        }

        accumulated = true;
    }

    // Guard: if no challenge items were accumulated, return empty result
    if (!accumulated) {
        spdlog::warn("DHTDynamicAuditStrategy::generateProofs: no valid challenge items accumulated");
        return result;
    }

    // ========== Step 3: Compute Λ = e(u, R)^M ==========
    SM9GTElement Lambda;
    if (!Lambda.pairing(u, R)) {
        spdlog::error("DHTDynamicAuditStrategy::generateProofs: pairing(u, R) failed");
        return result;
    }

    auto lambda_m = Lambda ^ M;  // returns shared_ptr<GTElement>
    if (lambda_m) {
        Lambda.assign(*lambda_m);
    }

    // ========== Assemble proof ==========
    auto proves = std::make_shared<DHTDynamicProves>();
    proves->setTheta(Theta);
    proves->setLambda(Lambda);

    result.proves = proves;
    result.ext = input.ext;
    return result;
}

// ========================================================================
// Proof Verification
// ========================================================================

CAMatrix::Audit::Messages::VerifyProofsResult DHTDynamicAuditStrategy::verifyProofs(
    const CAMatrix::Audit::Messages::VerifyProofsRequest& input)
{
    CAMatrix::Audit::Messages::VerifyProofsResult result;

    // DHTDynamic only supports single verification — extract first element from vectors
    if (input.challenges.empty() || input.proves.empty()) {
        result.ok = false;
        result.reason = "Empty challenges or proves vector";
        return result;
    }

    auto ext = std::dynamic_pointer_cast<DHTDynamicVerifyRequestExt>(input.ext);
    auto challenges = std::dynamic_pointer_cast<DHTDynamicChallenges>(input.challenges[0]);
    auto proves = std::dynamic_pointer_cast<DHTDynamicProves>(input.proves[0]);
    if (!ext || !challenges || !proves) {
        result.ok = false;
        result.reason = "DHTDynamicVerifyRequestExt/Challenges/Proves required";
        return result;
    }

    if (ext->fileId.empty()) {
        result.ok = false;
        result.reason = "fileId required for verification";
        return result;
    }

    if (!ext->userPublicParams) {
        result.ok = false;
        result.reason = "User public params required for verification";
        return result;
    }

    // Guard: empty challenge items
    if (challenges->items().empty()) {
        result.ok = false;
        result.reason = "No challenge items — challengeCount was zero or not set";
        return result;
    }

    const G2Point& pk = ext->userPublicParams->pk;

    // Guard: pk must not be at infinity
    if (pk.isInfinity()) {
        result.ok = false;
        result.reason = "Public key pk is at infinity — invalid user params";
        return result;
    }

    // ========== Step 1: Compute H = Σ(ν_j · H₁(fileId‖i_j)) ∈ G₁ ==========
    //
    // The verifier computes the aggregated hash point H from the challenge
    // items, using the same hashToCurve function as tag generation.
    // This is the key difference from the naive Θ == Λ check — the correct
    // verification equation is Θ^r == Λ · e(H, R).

    G1Point H;  // H = Σ(ν_j · H_{i_j}) — aggregated weighted hash point
    H.setInfinity();
    bool hAccumulated = false;

    for (const auto& item : challenges->items()) {
        // Compute H_{i_j} = hashToCurve(fileId‖i_j‖metadata.serialize()) ∈ G₁
        // TPA uses the metadata from its DHT (carried in the challenge item)
        const G1Point H_ij = DHTDynamic::computeBlockHash(
            ext->fileId, item.blockIndex, item.metadata);

        // [ν_j]·H_{i_j} — scalar multiplication on G₁
        auto nuH = H_ij * item.nu;
        auto nuHPoint = std::static_pointer_cast<G1Point>(nuH);

        // H += [ν_j]·H_{i_j} — accumulate on G₁
        auto newH = H + *nuHPoint;
        auto newHPoint = std::static_pointer_cast<G1Point>(newH);
        H.assign(*newHPoint);
        hAccumulated = true;
    }

    if (!hAccumulated) {
        result.ok = false;
        result.reason = "No valid challenge items for H computation";
        return result;
    }

    // ========== Step 2: Compute Θ^r ==========
    const SM9GTElement& Theta = proves->theta();
    const SM9CryptoData& r = challenges->r();
    auto thetaR = Theta ^ r;  // Θ^r ∈ GT
    if (!thetaR) {
        result.ok = false;
        result.reason = "Failed to compute Θ^r";
        return result;
    }

    // ========== Step 3: Compute Λ · e(H, R) ==========
    const SM9GTElement& Lambda = proves->lambda();
    const G2Point& R = challenges->R();

    // e(H, R) — pairing of aggregated hash with blind commitment
    SM9GTElement eHR;
    if (!eHR.pairing(H, R)) {
        result.ok = false;
        result.reason = "Failed to compute e(H, R)";
        return result;
    }

    // Λ · e(H, R) — multiply in GT
    auto rhs = Lambda * eHR;
    if (!rhs) {
        result.ok = false;
        result.reason = "Failed to compute Λ · e(H, R)";
        return result;
    }

    // ========== Step 4: Check Θ^r == Λ · e(H, R) ==========
    result.ok = (*thetaR == *rhs);
    result.reason = result.ok ? "OK" : "Verification failed: Θ^r ≠ Λ · e(H, R)";

    result.ext = input.ext;
    return result;
}

} // namespace CAMatrix::Audit::Strategies
