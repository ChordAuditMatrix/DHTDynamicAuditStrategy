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
 * @file artifact_factory.h
 * @brief Declares the DHTDynamic-specific audit artifact factory
 * @details This factory is owned conceptually by the DHTDynamic audit strategy
 *          and is used by AuditEngine::createArtifact() through the strategy boundary.
 *          It centralizes reconstruction of all DHTDynamic-specific abstract artifacts:
 *          - AlgorithmPublicParams → DHTDynamicAlgoPublicParams
 *          - AlgorithmPrivateParams → DHTDynamicAlgoPrivateParams
 *          - UserPublicParams → DHTDynamicPublicParams
 *          - UserPrivateParams → DHTDynamicPrivateParams
 *          - Tag → DHTDynamicTag
 *          - Challenges → DHTDynamicChallenges
 *          - Proves → DHTDynamicProves
 *          - DynamicBlockMetadata → VersionedBlockMetadata
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-06
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef CAMATRIX_DHT_DYNAMIC_AUDIT_ARTIFACT_FACTORY_H
#define CAMATRIX_DHT_DYNAMIC_AUDIT_ARTIFACT_FACTORY_H

#include "ChordAuditMatrixLib/interfaces/audit/artifact_factory.h"

namespace CAMatrix::Audit::Strategies {

/**
 * @class DHTDynamicAuditArtifactFactory
 * @brief Creates DHTDynamic-backed audit artifacts for engine-driven reconstruction
 */
class DHTDynamicAuditArtifactFactory final : public ::CAMatrix::Audit::Core::AuditStrategyArtifactFactory {
public:
    /**
     * @brief Creates one empty abstract artifact instance for the requested kind
     * @param kind [IN] Requested abstract artifact category
     * @return AuditArtifactVariant, Variant holding the concrete DHTDynamic-backed artifact
     */
    ::CAMatrix::Audit::Core::AuditArtifactVariant createArtifact(
        ::CAMatrix::Audit::Core::AuditArtifactKind kind) const override;
};

} // namespace CAMatrix::Audit::Strategies

#endif // CAMATRIX_DHT_DYNAMIC_AUDIT_ARTIFACT_FACTORY_H
