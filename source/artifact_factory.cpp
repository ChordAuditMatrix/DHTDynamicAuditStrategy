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
 * @file artifact_factory.cpp
 * @brief Implements the DHTDynamic-specific audit artifact factory
 * @details Creates empty concrete artifact instances for all 8 AuditArtifactKind
 *          values, mapping each to the DHTDynamic strategy's concrete types:
 *          - AlgorithmPublicParams → DHTDynamicAlgoPublicParams (empty)
 *          - AlgorithmPrivateParams → DHTDynamicAlgoPrivateParams (empty)
 *          - UserPublicParams → DHTDynamicPublicParams (pk, g, y, u)
 *          - UserPrivateParams → DHTDynamicPrivateParams (sk, a)
 *          - Tag → DHTDynamicTag
 *          - Challenges → DHTDynamicChallenges
 *          - Proves → DHTDynamicProves
 *          - DynamicBlockMetadata → VersionedBlockMetadata
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-08
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/artifact_factory.h"

#include "DHTDynamicAuditStrategy/state_stores/versioned_block_metadata.h"
#include "DHTDynamicAuditStrategy/challenges.h"
#include "DHTDynamicAuditStrategy/params.h"
#include "DHTDynamicAuditStrategy/proves.h"
#include "DHTDynamicAuditStrategy/tags.h"

#include <spdlog/spdlog.h>

#include <stdexcept>

namespace CAMatrix::Audit::Strategies {

using namespace DHTDynamic;

namespace {

template<typename T>
CAMatrix::Audit::Core::AuditArtifactVariant makeArtifactVariant(std::shared_ptr<T> artifact)
{
    CAMatrix::Audit::Core::AuditArtifactVariant variant;
    variant.template emplace<std::shared_ptr<T>>(std::move(artifact));
    return variant;
}

} // namespace

CAMatrix::Audit::Core::AuditArtifactVariant DHTDynamicAuditArtifactFactory::createArtifact(
    CAMatrix::Audit::Core::AuditArtifactKind kind) const
{
    spdlog::trace("DHTDynamicArtifactFactory: createArtifact kind={}", static_cast<int>(kind));

    using namespace CAMatrix::Audit::Messages;
    using namespace CAMatrix::Audit::Core;

    switch (kind) {
        case AuditArtifactKind::AlgorithmPublicParams: {
            auto params = std::make_shared<DHTDynamicAlgoPublicParams>();
            return makeArtifactVariant<AlgoPublicParams>(
                std::static_pointer_cast<AlgoPublicParams>(params));
        }
        case AuditArtifactKind::AlgorithmPrivateParams: {
            auto params = std::make_shared<DHTDynamicAlgoPrivateParams>();
            return makeArtifactVariant<AlgoPrivateParams>(
                std::static_pointer_cast<AlgoPrivateParams>(params));
        }
        case AuditArtifactKind::UserPublicParams: {
            auto params = std::make_shared<DHTDynamicPublicParams>();
            return makeArtifactVariant<AlgoPublicParams>(
                std::static_pointer_cast<AlgoPublicParams>(params));
        }
        case AuditArtifactKind::UserPrivateParams: {
            auto params = std::make_shared<DHTDynamicPrivateParams>();
            return makeArtifactVariant<AlgoPrivateParams>(
                std::static_pointer_cast<AlgoPrivateParams>(params));
        }
        case AuditArtifactKind::Tag:
            return makeArtifactVariant<Tag>(
                std::static_pointer_cast<Tag>(std::make_shared<DHTDynamicTag>()));
        case AuditArtifactKind::Challenges:
            return makeArtifactVariant<Challenges>(
                std::static_pointer_cast<Challenges>(std::make_shared<DHTDynamicChallenges>()));
        case AuditArtifactKind::Proves:
            return makeArtifactVariant<Proves>(
                std::static_pointer_cast<Proves>(std::make_shared<DHTDynamicProves>()));
        case AuditArtifactKind::DynamicBlockMetadata:
            return makeArtifactVariant<BlockMetadata>(
                std::static_pointer_cast<BlockMetadata>(std::make_shared<VersionedBlockMetadata>()));
    }

    spdlog::debug("DHTDynamicArtifactFactory: unsupported artifact kind={}", static_cast<int>(kind));
    throw std::runtime_error("unsupported audit artifact kind for DHTDynamic strategy");
}

} // namespace CAMatrix::Audit::Strategies
