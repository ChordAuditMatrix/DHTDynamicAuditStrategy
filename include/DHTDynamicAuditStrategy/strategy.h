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
 * @file strategy.h
 * @brief DHT-based dynamic provable data possession (PDP) audit strategy
 * @details Implements a dynamic PDP scheme using BLS signatures on SM9 curves
 *          with DHT-based state management:
 *
 *          **Algorithm Overview:**
 *          - Setup: No KGC; algorithm init is a no-op
 *          - KeyGen: Generate random a, sk, r, r';
 *            g = [r]·G₂, y = [a]·g, u = [r']·G₁, pk = [sk]·G₂
 *          - TagGen: For each block m_i, compute tag
 *            σ_i = [a]·(H_i + Σ[segment_j]·u)
 *            where H_i = hashToCurve(fileId‖i‖version‖timestamp)
 *            with BlockMetadata{version=1, timestamp=now()}
 *          - Maintenance: Support Update/Insert/Delete with DHT state updates.
 *            maintenance() only updates StateStore; tag management is the
 *            caller's responsibility (generateTags() → Storage).
 *          - Challenge: Select random subset {(i_j, ν_j)};
 *            R = [r]·y, metadata from stateStore
 *          - Prove: Compute
 *            θ_{i_j} = e(σ_{i_j}, g)
 *            Θ = ∏ θ_{i_j}^{ν_j}
 *            M = Σ(ν_j · m_{i_j})
 *            Λ = e(u, R)^M
 *          - Verify: Check Θ == Λ
 *
 *          **Properties:**
 *          - BLS aggregate signatures on SM9 pairing-friendly curves
 *          - Dynamic: supports Update, Insert, Delete operations
 *          - TPA-maintained state via DHT
 *          - Batch verification via pairing aggregation
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-06
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef CAMATRIX_DHT_DYNAMIC_AUDIT_STRATEGY_H
#define CAMATRIX_DHT_DYNAMIC_AUDIT_STRATEGY_H

#include "ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h"
#include "DHTDynamicAuditStrategy/state_stores/dynamic_hash_table_state_store.h"
#include <memory>

namespace CAMatrix::Audit::Strategies::DHTDynamic {
class DHTDynamicMaintainExt;
} // namespace CAMatrix::Audit::Strategies::DHTDynamic

namespace CAMatrix::Audit::Strategies {

/**
 * @class DHTDynamicAuditStrategy
 * @brief DHT-based dynamic PDP implementation
 * @details State maintenance party is TPA (Third-Party Auditor).
 *          StateStore must be injected via setStateStore() before calling
 *          maintenance() or any operation that depends on DHT state.
 */
class DHTDynamicAuditStrategy : public ::CAMatrix::Audit::Core::DynamicAuditStrategy {
public:
    /**
     * @brief Constructs a DHTDynamic audit strategy instance
     */
    DHTDynamicAuditStrategy();

    // ── Strategy identification ──

    /**
     * @brief Returns the algorithm type identifier
     * @return std::string, "DHTDynamic"
     */
    std::string algorithmType() const override { return "DHTDynamic"; }

    /**
     * @brief Returns the strategy version
     * @return std::string, "1.0.0"
     */
    std::string version() const override { return "1.0.0"; }

    /**
     * @brief Returns the capabilities of this strategy
     * @return Capabilities, IdentityAuthentication | DynamicUpdate
     * @details BatchVerify not yet implemented
     */
    ::CAMatrix::Audit::Messages::Capabilities caps() const override;

    // ── State maintenance party ──

    /**
     * @brief Returns TPA as the state maintenance party
     * @return StateMaintenanceParty::TPA
     * @details In DHTDynamic, the TPA maintains the DHT state structure
     *          that tracks block metadata for dynamic operations
     */
    CAMatrix::Audit::Core::StateMaintenanceParty stateMaintenanceParty() const override {
        return ::CAMatrix::Audit::Core::StateMaintenanceParty::TPA;
    }

    // ── State store creation ──

    /**
     * @brief Create a DynamicHashTableStateStore for this strategy
     * @param metadataFactory [IN] Factory for creating BlockMetadata instances
     * @return shared_ptr<DynamicPdpStateStore>, New DynamicHashTableStateStore
     * @details Returns the DHTDynamic-owned DynamicHashTableStateStore so that
     *          the strategy uses its own state store implementation rather than
     *          the CoreLib default.
     */
    std::shared_ptr<::CAMatrix::Audit::Core::DynamicPdpStateStore>
        createStateStore(::CAMatrix::Audit::Core::BlockMetadataFactory metadataFactory) const override {
        return std::make_shared<::CAMatrix::Audit::Core::DynamicHashTableStateStore>(std::move(metadataFactory));
    }

    // ── Algorithm injection ──

    /**
     * @brief Set the cryptographic algorithm implementation
     * @param algorithm [IN] Crypto algorithm pointer
     */
    void setAlgorithm(::CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm) override;

    // ── Seven-stage audit pipeline ──

    /**
     * @brief Initialize algorithm parameters
     * @param input [IN] InitializeAlgorithmRequest with optional seed
     * @return InitializeAlgorithmResult, with algorithm parameters
     */
    ::CAMatrix::Audit::Messages::InitializeAlgorithmResult initializeAlgorithm(
        const ::CAMatrix::Audit::Messages::InitializeAlgorithmRequest& input) override;

    /**
     * @brief Generate user key pair
     * @param input [IN] GenerateKeysRequest with optional seed
     * @return GenerateKeysResult, with user key pair
     */
    ::CAMatrix::Audit::Messages::GenerateKeysResult generateKeys(
        const ::CAMatrix::Audit::Messages::GenerateKeysRequest& input) override;

    /**
     * @brief Generate tags for file blocks
     * @param input [IN] GenerateTagsRequest with file blocks and user keys
     * @return GenerateTagsResult, with generated tags
     */
    ::CAMatrix::Audit::Messages::GenerateTagsResult generateTags(
        const ::CAMatrix::Audit::Messages::GenerateTagsRequest& input) override;

    /**
     * @brief Generate challenge set for audit
     * @param input [IN] GenerateChallengesRequest with challenge parameters
     * @return GenerateChallengesResult, with challenge items and blind commitment
     */
    ::CAMatrix::Audit::Messages::GenerateChallengesResult generateChallenges(
        const ::CAMatrix::Audit::Messages::GenerateChallengesRequest& input) override;

    /**
     * @brief Generate proof from challenges and stored data
     * @param input [IN] GenerateProofsRequest with challenges, tags, and blocks
     * @return GenerateProofsResult, with aggregate proof (Θ, Λ)
     */
    ::CAMatrix::Audit::Messages::GenerateProofsResult generateProofs(
        const ::CAMatrix::Audit::Messages::GenerateProofsRequest& input) override;

    /**
     * @brief Verify proof correctness
     * @param input [IN] VerifyProofsRequest with proof and challenge data
     * @return VerifyProofsResult, indicating pass/fail
     */
    ::CAMatrix::Audit::Messages::VerifyProofsResult verifyProofs(
        const ::CAMatrix::Audit::Messages::VerifyProofsRequest& input) override;

    // ── Dynamic PDP maintenance ──

    /**
     * @brief Perform dynamic maintenance (Update/Insert/Delete)
     * @param input [IN] MaintainRequest with operation type and block data
     * @return MaintainResult, indicating success/failure
     */
    ::CAMatrix::Audit::Messages::MaintainResult maintenance(
        const ::CAMatrix::Audit::Messages::MaintainRequest& input) override;

    // ── Request creation ──

    /**
     * @brief Create a typed request from raw input
     * @param op [IN] Audit operation type
     * @param context [IN] Audit operation context
     * @param rawInput [IN] Raw input data
     * @return AuditRequestVariantPtr, Typed request variant
     */
    ::CAMatrix::Audit::Messages::AuditRequestVariantPtr createRequest(
        ::CAMatrix::Audit::Core::AuditOperation op,
        const ::CAMatrix::Audit::Core::AuditOperationContext& context,
        const ::CAMatrix::Audit::Messages::RawInput& rawInput = ::CAMatrix::Audit::Messages::RawInput()) override;

protected:
    /**
     * @brief Returns the DHTDynamic-owned artifact factory implementation
     * @return const AuditStrategyArtifactFactory&, DHTDynamic artifact factory
     */
    const ::CAMatrix::Audit::Core::AuditStrategyArtifactFactory& artifactFactory() const override;

private:
    ::CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm_;

    // ── Maintenance operation handlers ──

    /**
     * @brief Handle Update operation
     * @details Bumps version and refreshes timestamp in StateStore via modifyBlock().
     *          Tag management is the caller's responsibility.
     * @param ext [IN] DHTDynamic maintenance extension data
     * @param now [IN] Current timestamp
     * @return MaintainResult, indicating success/failure
     */
    ::CAMatrix::Audit::Messages::MaintainResult handleUpdate(
        std::shared_ptr<DHTDynamic::DHTDynamicMaintainExt> ext,
        std::uint64_t now);

    /**
     * @brief Handle Insert operation
     * @details Inserts BlockMetadata into StateStore via insertBlock().
     *          Tag management is the caller's responsibility.
     * @param ext [IN] DHTDynamic maintenance extension data
     * @param now [IN] Current timestamp
     * @return MaintainResult, indicating success/failure
     */
    ::CAMatrix::Audit::Messages::MaintainResult handleInsert(
        std::shared_ptr<DHTDynamic::DHTDynamicMaintainExt> ext,
        std::uint64_t now);

    /**
     * @brief Handle Delete operation
     * @details Deletes BlockMetadata from StateStore via deleteBlock().
     *          Tag management is the caller's responsibility.
     * @param ext [IN] DHTDynamic maintenance extension data
     * @return MaintainResult, indicating success/failure
     */
    ::CAMatrix::Audit::Messages::MaintainResult handleDelete(
        std::shared_ptr<DHTDynamic::DHTDynamicMaintainExt> ext);
};

} // namespace CAMatrix::Audit::Strategies

#endif // CAMATRIX_DHT_DYNAMIC_AUDIT_STRATEGY_H
