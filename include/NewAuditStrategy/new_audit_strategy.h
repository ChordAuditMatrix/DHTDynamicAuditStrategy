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
 * @file new_audit_strategy.h
 * @brief Template for implementing a custom audit strategy as a shared library plugin.
 * @details This file provides a skeleton implementation of a static audit strategy
 *          that can be loaded at runtime by the ChordAuditMatrix hot-load system.
 *
 *          The template inherits from `StaticAuditStrategy` and implements all
 *          required virtual methods of the 7-stage PDP pipeline with empty stubs.
 *          Users should fill in the actual cryptographic logic for their custom
 *          audit algorithm.
 *
 *          The C-linkage factory functions `create_audit_strategy()` and
 *          `destroy_audit_strategy()` are automatically exported for dynamic
 *          loading via `dlopen`/`dlsym`.
 *
 * @author Dylan Liu
 * @version 2.0.0
 * @date 2026-07-12
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef NEW_AUDIT_STRATEGY_H
#define NEW_AUDIT_STRATEGY_H

#include "ChordAuditMatrixLib/interfaces/audit/static_strategy.h"
#include "ChordAuditMatrixLib/interfaces/audit/artifact_factory.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/request_result.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/raw_input.h"
#include "ChordAuditMatrixLib/interfaces/audit/operation_context.h"

#include <memory>
#include <stdexcept>

namespace CAMatrix::Audit::Strategies {

/**
 * @class NewAuditStrategy
 * @brief Skeleton implementation of a custom static audit strategy.
 * @details Users should inherit from `StaticAuditStrategy` (for static PDP schemes)
 *          or `DynamicAuditStrategy` (for dynamic/updatable schemes) and implement
 *          all pure virtual methods of the 7-stage pipeline:
 *
 *          1. `initializeAlgorithm()` — Set up algorithm parameters and public keys
 *          2. `generateKeys()`       — Generate key pairs (sk, pk)
 *          3. `generateTags()`       — Compute authenticator tags σ_i for each block
 *          4. `generateChallenges()` — TPA generates random challenge set
 *          5. `generateProofs()`     — CSP computes proof from challenged blocks
 *          6. `verifyProofs()`       — TPA verifies proof against tags and challenges
 *
 *          For dynamic strategies, also implement:
 *          - `maintenance()` — Handle Insert/Update/Delete operations on blocks
 *
 *          Each stage uses strongly-typed Request/Result structs instead of
 *          the legacy AuditDataPack variant map.
 */
class NewAuditStrategy : public CAMatrix::Audit::Core::StaticAuditStrategy {
public:
    NewAuditStrategy();
    ~NewAuditStrategy() override;

    // ── PluggableAlgorithm interface ──

    std::string algorithmType() const override { return "NewAudit"; }
    std::string version() const override { return "1.0.0"; }
    CAMatrix::Audit::Messages::Capabilities caps() const override;

    // ── AuditStrategy interface: algorithm injection ──

    void setAlgorithm(CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm) override;

    // ── 7-stage PDP pipeline ──

    CAMatrix::Audit::Messages::InitializeAlgorithmResult initializeAlgorithm(
        const CAMatrix::Audit::Messages::InitializeAlgorithmRequest& input) override;

    CAMatrix::Audit::Messages::GenerateKeysResult generateKeys(
        const CAMatrix::Audit::Messages::GenerateKeysRequest& input) override;

    CAMatrix::Audit::Messages::GenerateTagsResult generateTags(
        const CAMatrix::Audit::Messages::GenerateTagsRequest& input) override;

    CAMatrix::Audit::Messages::GenerateChallengesResult generateChallenges(
        const CAMatrix::Audit::Messages::GenerateChallengesRequest& input) override;

    CAMatrix::Audit::Messages::GenerateProofsResult generateProofs(
        const CAMatrix::Audit::Messages::GenerateProofsRequest& input) override;

    CAMatrix::Audit::Messages::VerifyProofsResult verifyProofs(
        const CAMatrix::Audit::Messages::VerifyProofsRequest& input) override;

    // ── Request creation (RawInput → strongly-typed) ──

    CAMatrix::Audit::Messages::AuditRequestVariantPtr createRequest(
        CAMatrix::Audit::Core::AuditOperation op,
        const CAMatrix::Audit::Core::AuditOperationContext& context,
        const CAMatrix::Audit::Messages::RawInput& rawInput = CAMatrix::Audit::Messages::RawInput()) override;

protected:
    // ── Artifact factory ──

    const CAMatrix::Audit::Core::AuditStrategyArtifactFactory& artifactFactory() const override;

private:
    CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm_;
    std::unique_ptr<CAMatrix::Audit::Core::AuditStrategyArtifactFactory> artifactFactory_;
};

} // namespace CAMatrix::Audit::Strategies

// ── C-linkage factory functions for dynamic loading ──
// These are resolved by AlgorithmRegistry via dlsym/GetProcAddress.
//
// Both create_audit_strategy() and destroy_audit_strategy() are declared
// inside namespace CAMatrix::Audit::Core in CoreLib's strategy.h, where
// destroy_audit_strategy() is also declared as a friend of AuditStrategy
// (so it can access the protected destructor). Defining them in the same
// namespace here makes the friend declaration apply — GCC enforces this,
// while MSVC and Clang are more permissive. The `extern "C"` linkage keeps
// the exported symbol names compatible with dlsym/GetProcAddress.
namespace CAMatrix::Audit::Core {
extern "C" AuditStrategy* create_audit_strategy() noexcept
{
    return new CAMatrix::Audit::Strategies::NewAuditStrategy();
}

extern "C" void destroy_audit_strategy(AuditStrategy* p) noexcept
{
    delete p;
}
} // namespace CAMatrix::Audit::Core

#endif // NEW_AUDIT_STRATEGY_H