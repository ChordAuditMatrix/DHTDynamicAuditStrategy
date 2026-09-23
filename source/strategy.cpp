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
 * @file strategy.cpp
 * @brief Core implementation of DHT-based dynamic PDP audit strategy
 * @details Contains constructor, destructor, caps(), setAlgorithm(),
 *          artifactFactory(), and createRequest().
 *          Uses SM9BLSAlgorithm and SM9BLSCryptoStrategy for the
 *          BLS-based audit scheme.
 *          Stage implementations are in separate files:
 *          - initialize_algorithm.cpp: Algorithm initialization (no-op)
 *          - generate_keys.cpp: Key generation (random a, sk, r, r')
 *          - generate_tags.cpp: Tag generation (BLS signatures)
 *          - generate_challenges.cpp: Challenge generation
 *          - generate_proofs.cpp: Proof generation + verification
 *          - maintain.cpp: Dynamic maintenance (Update/Insert/Delete)
 */

#include "DHTDynamicAuditStrategy/strategy.h"
#include "DHTDynamicAuditStrategy/artifact_factory.h"
#include "DHTDynamicAuditStrategy/common.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/algorithm.h"
#include "ChordAuditMatrixLib/implementations/crypto/sm9_bls/strategy.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"
#include "json/json.h"
#include "spdlog/spdlog.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <sstream>
#include <variant>

namespace CAMatrix::Audit::Strategies {

using namespace DHTDynamic;

DHTDynamicAuditStrategy::DHTDynamicAuditStrategy()
    : algorithm_(std::make_shared<CAMatrix::Crypto::SM9BLS::SM9BLSAlgorithm>())
{
    algorithm_->setCryptoStrategy(std::make_shared<CAMatrix::Crypto::SM9BLS::SM9BLSCryptoStrategy>());
    spdlog::debug("DHTDynamicStrategy: constructed with SM9BLSAlgorithm injected");
}

CAMatrix::Audit::Messages::Capabilities DHTDynamicAuditStrategy::caps() const
{
    // BatchVerify is NOT currently supported — verifyProofs() only extracts
    // the first element from the challenges/proves vectors (aggregated PDP
    // verification, not batch verification of independent proofs).
    // Remove BatchVerify from caps until true batch verification is implemented.
    return static_cast<CAMatrix::Audit::Messages::Capabilities>(
        static_cast<std::uint32_t>(CAMatrix::Audit::Messages::Capabilities::IdentityAuthentication) |
        static_cast<std::uint32_t>(CAMatrix::Audit::Messages::Capabilities::DynamicUpdate));
}

const CAMatrix::Audit::Core::AuditStrategyArtifactFactory& DHTDynamicAuditStrategy::artifactFactory() const
{
    static DHTDynamicAuditArtifactFactory factory;
    return factory;
}

void DHTDynamicAuditStrategy::setAlgorithm(CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm)
{
    algorithm_ = std::move(algorithm);
}

CAMatrix::Audit::Messages::AuditRequestVariantPtr DHTDynamicAuditStrategy::createRequest(
    CAMatrix::Audit::Core::AuditOperation op,
    const CAMatrix::Audit::Core::AuditOperationContext& context,
    const CAMatrix::Audit::Messages::RawInput& rawInput)
{
    using namespace CAMatrix::Audit::Core;
    using namespace CAMatrix::Audit::Messages;

    switch (op) {
        case AuditOperation::AlgorithmInit: {
            auto req = std::make_shared<InitializeAlgorithmRequest>();
            auto ext = std::make_shared<DHTDynamicAlgoInitRequestExt>();
            req->ext = ext;
            return std::make_shared<AuditRequestVariant>(req);
        }

        case AuditOperation::KeyGeneration: {
            auto req = std::make_shared<GenerateKeysRequest>();
            auto ext = std::make_shared<DHTDynamicKeyGenRequestExt>();

            // Parse the optional deterministic-key seed from the JSON rawInput.
            // "seed" is DHTDynamic-specific and consumer-only: the shared
            // KeyGeneration contract (KeyGenerationEngineContract::Env) declares
            // kUserId, while no first-party producer (admin user bind, Bench)
            // writes this key yet, so the literal stays here.
            const Json::Value root = rawInput.requireJson(op);

            if (root.isMember("seed") && root["seed"].isUInt64()) {
                ext->seed = root["seed"].asUInt64();
            }

            req->ext = ext;
            return std::make_shared<AuditRequestVariant>(req);
        }

        case AuditOperation::GenerateTags: {
            auto req = std::make_shared<GenerateTagsRequest>();
            auto ext = std::make_shared<DHTDynamicTagsGenRequestExt>();

            // Retrieve generateKeys result from context
            if (!context.generateKeysResult) {
                throw std::runtime_error("GenerateTags requires generateKeys result in context");
            }

            ext->userPublicParams = std::dynamic_pointer_cast<DHTDynamicPublicParams>(
                context.generateKeysResult->publicParams);
            ext->userPrivateParams = std::dynamic_pointer_cast<DHTDynamicPrivateParams>(
                context.generateKeysResult->privateParams);

            if (!ext->userPublicParams || !ext->userPrivateParams) {
                throw std::runtime_error("GenerateTags requires DHTDynamic public/private params from generateKeys");
            }

            // Parse fileId and blocks from Custom rawInput
            auto inputMap = rawInput.requireCustom<AuditDataMap>(op);
            using TagsKeys = GenerateTagsEngineContract::Env;

            // Extract blocks (required)
            req->blocks = inputMap->getRequired<std::shared_ptr<CAMatrix::Audit::Data::AuditBlockSource>>(
                std::string(TagsKeys::kBlocks));

            // Extract fileId (required)
            if (auto fileId = inputMap->getOptional<std::string>(std::string(TagsKeys::kFileId))) {
                ext->fileId = *fileId;
            }

            if (ext->fileId.empty()) {
                throw std::runtime_error("GenerateTags requires 'fileId' in Custom data");
            }

            // Extract targetBlockIndices (optional): when present, only blocks at
            // the given 1-based GLOBAL indices are tagged; an empty selector means
            // "full window".  A present key MUST hold std::vector<std::size_t>:
            // a wrong-typed value is rejected here instead of being treated as
            // "absent" (which would silently tag the whole window).
            if (const auto it = inputMap->find(std::string(TagsKeys::kTargetBlockIndices));
                it != inputMap->end()) {
                if (const auto* selector = std::any_cast<std::vector<std::size_t>>(&it->second)) {
                    req->targetBlockIndices = *selector;
                } else {
                    throw std::runtime_error(
                        "GenerateTags '" + std::string(TagsKeys::kTargetBlockIndices) +
                        "' must be std::vector<std::size_t> (1-based global block indices)");
                }
            }

            req->ext = ext;
            return std::make_shared<AuditRequestVariant>(req);
        }

        case AuditOperation::ChallengeGen: {
            auto req = std::make_shared<GenerateChallengesRequest>();
            auto ext = std::make_shared<DHTDynamicChallengeRequestExt>();

            // Parse challenge parameters from JSON rawInput
            const Json::Value root = rawInput.requireJson(op);
            using ChalKeys = ChallengeGenEngineContract::Env;

            bool hasBlockCount = false;
            if (root.isMember(ChalKeys::kBlockCount) && root[ChalKeys::kBlockCount].isUInt64()) {
                ext->blockCount = static_cast<std::size_t>(root[ChalKeys::kBlockCount].asUInt64());
                hasBlockCount = true;
            }

            if (root.isMember(ChalKeys::kChallengeCount) && root[ChalKeys::kChallengeCount].isUInt64()) {
                ext->challengeCount = static_cast<std::size_t>(root[ChalKeys::kChallengeCount].asUInt64());
            }

            if (root.isMember(ChalKeys::kUsePseudoRandom) && root[ChalKeys::kUsePseudoRandom].isBool()) {
                ext->usePseudoRandom = root[ChalKeys::kUsePseudoRandom].asBool();
            }

            if (root.isMember(ChalKeys::kSeed) && root[ChalKeys::kSeed].isUInt64()) {
                ext->seed = root[ChalKeys::kSeed].asUInt64();
            }

            // Parse fileId from JSON rawInput (required for stateStore queries)
            if (root.isMember(ChalKeys::kFileId) && root[ChalKeys::kFileId].isString()) {
                ext->fileId = root[ChalKeys::kFileId].asString();
            }

            // Fill missing fileId from context (generateTagsResult ext)
            if (ext->fileId.empty() && context.generateTagsResult && context.generateTagsResult->ext) {
                auto prevExt = std::dynamic_pointer_cast<DHTDynamicTagsGenRequestExt>(
                    context.generateTagsResult->ext);
                if (prevExt) {
                    ext->fileId = prevExt->fileId;
                }
            }

            // Retrieve userPublicParams from context (for y point to compute R = [r]·y)
            if (context.generateKeysResult) {
                ext->userPublicParams = std::dynamic_pointer_cast<DHTDynamicPublicParams>(
                    context.generateKeysResult->publicParams);
            }

            // Retrieve tags from context to determine valid block indices
            if (context.generateTagsResult && context.generateTagsResult->tags) {
                req->tags = context.generateTagsResult->tags;
            }

            if (!hasBlockCount && !context.generateTagsResult) {
                throw std::runtime_error(
                    "GenerateChallenges requires either 'blockCount' in input or generateTagsResult in context");
            }

            req->ext = ext;
            return std::make_shared<AuditRequestVariant>(req);
        }

        case AuditOperation::ProofGen: {
            auto req = std::make_shared<GenerateProofsRequest>();
            auto ext = std::make_shared<DHTDynamicProveRequestExt>();

            // Retrieve challenges from context
            if (!context.generateChallengesResult || !context.generateChallengesResult->challenges) {
                throw std::runtime_error("GenerateProofs requires challenges in context");
            }

            req->challenges = context.generateChallengesResult->challenges;

            // Parse blocks and tags from Custom rawInput
            auto inputMap = rawInput.requireCustom<AuditDataMap>(op);
            using ProveKeys = ProofGenEngineContract::Env;

            ext->blocks = inputMap->getRequired<std::shared_ptr<CAMatrix::Audit::Data::AuditBlockSource>>(
                std::string(ProveKeys::kBlocks));
            ext->tags = inputMap->getRequired<std::shared_ptr<CAMatrix::Audit::Messages::Tags>>(
                std::string(ProveKeys::kTags));

            // Retrieve userPublicParams from context
            if (context.generateKeysResult) {
                ext->userPublicParams = std::dynamic_pointer_cast<DHTDynamicPublicParams>(
                    context.generateKeysResult->publicParams);
            }

            if (!ext->userPublicParams) {
                throw std::runtime_error("GenerateProofs requires DHTDynamic public params from context");
            }

            req->ext = ext;
            return std::make_shared<AuditRequestVariant>(req);
        }

        case AuditOperation::ProofVerify: {
            auto req = std::make_shared<VerifyProofsRequest>();
            auto ext = std::make_shared<DHTDynamicVerifyRequestExt>();

            // Retrieve challenges and proves from context
            if (!context.generateChallengesResult || !context.generateProofsResult) {
                throw std::runtime_error("VerifyProofs requires challenges and proves in context");
            }

            req->challenges = {context.generateChallengesResult->challenges};
            req->proves = {context.generateProofsResult->proves};

            // The verify stage is handed the challenge session's two parameter
            // slots (see ProofVerifyEngineContract::Frames): algorithm public
            // parameters and user public parameters. This strategy verifies
            // with pairings over the user public key only, so it consumes the
            // session's user-parameter role and never the algorithm role. The
            // role it relies on is pinned to the declared contract.
            using VerifySlots = ProofVerifyEngineContract::Frames;
            static_assert(VerifySlots::kUserPublicParamsKind ==
                              CAMatrix::Audit::Core::AuditArtifactKind::UserPublicParams,
                          "DHTDynamic verify consumes the user public parameter role");
            static_assert(VerifySlots::kSlotCount == 2,
                          "the challenge session hands the verify stage two parameter roles");

            // Retrieve userPublicParams from context
            if (context.generateKeysResult) {
                ext->userPublicParams = std::dynamic_pointer_cast<DHTDynamicPublicParams>(
                    context.generateKeysResult->publicParams);
            }

            if (!ext->userPublicParams) {
                throw std::runtime_error(
                    "VerifyProofs requires the user-parameter role (slot " +
                    std::to_string(VerifySlots::kUserPublicParamsSlot) +
                    ") in context");
            }

            // Parse fileId from JSON rawInput
            const Json::Value root = rawInput.requireJson(op);
            using VerifyKeys = ProofVerifyEngineContract::Env;

            if (root.isMember(VerifyKeys::kFileId)) {
                std::string parsed;
                if (!RawInput::jsonValueToString(root[VerifyKeys::kFileId], parsed)) {
                    throw std::runtime_error("VerifyProofs 'fileId' must be string or byte array");
                }
                ext->fileId = parsed;
            }

            // Fill missing fileId from context
            if (ext->fileId.empty() && context.generateTagsResult && context.generateTagsResult->ext) {
                auto prevExt = std::dynamic_pointer_cast<DHTDynamicTagsGenRequestExt>(context.generateTagsResult->ext);
                if (prevExt) {
                    ext->fileId = prevExt->fileId;
                }
            }

            if (ext->fileId.empty()) {
                throw std::runtime_error("VerifyProofs requires 'fileId' in JSON input or context");
            }

            req->ext = ext;
            return std::make_shared<AuditRequestVariant>(req);
        }

        case AuditOperation::Maintenance: {
            // maintenance() only updates StateStore; tag management is the
            // caller's responsibility (generateTags() → Storage).
            auto req = std::make_shared<MaintainRequest>();
            auto ext = std::make_shared<DHTDynamicMaintainExt>();

            // Parse maintenance parameters from JSON rawInput. The keys come
            // from the CoreLib stage contract (MaintenanceEngineContract::Env),
            // which the first-party producers also write through.
            const Json::Value root = rawInput.requireJson(op);
            using MaintKeys = MaintenanceEngineContract::Env;

            // Extract fileId (required)
            if (!root.isMember(MaintKeys::kFileId) || !root[MaintKeys::kFileId].isString()) {
                throw std::runtime_error(
                    "Maintenance requires '" + std::string(MaintKeys::kFileId) + "' field");
            }
            ext->fileId = root[MaintKeys::kFileId].asString();

            // Extract opType (required)
            if (!root.isMember(MaintKeys::kOpType) || !root[MaintKeys::kOpType].isUInt()) {
                throw std::runtime_error(
                    "Maintenance requires '" + std::string(MaintKeys::kOpType) + "' field");
            }
            ext->opType = static_cast<CAMatrix::Audit::Messages::MaintenanceOpType>(
                root[MaintKeys::kOpType].asUInt());

            // Extract blockIndices. Absence is tolerated as "no indices", but a
            // present value MUST be an array: reading a wrong-typed value as
            // "no indices" would silently drop the operation's scope, so it is
            // rejected here instead of being defaulted (the producers also
            // validate the stage shape before this call).
            if (root.isMember(MaintKeys::kBlockIndices)) {
                if (!root[MaintKeys::kBlockIndices].isArray()) {
                    throw std::runtime_error(
                        "Maintenance '" + std::string(MaintKeys::kBlockIndices) +
                        "' must be an array of block indices");
                }
                for (const auto& idx : root[MaintKeys::kBlockIndices]) {
                    ext->blockIndices.push_back(static_cast<std::size_t>(idx.asUInt64()));
                }
            }

            req->type = ext->opType;
            req->ext = ext;
            return std::make_shared<AuditRequestVariant>(req);
        }

        default:
            throw std::runtime_error("DHTDynamicAuditStrategy: unknown AuditOperation type");
    }
}

} // namespace CAMatrix::Audit::Strategies

// ── C-linkage factory functions for dynamic loading ──
// Defined inside namespace CAMatrix::Audit::Core to match the friend
// declarations in strategy.h (so destroy can access the protected destructor).
// extern "C" linkage keeps the exported symbol names compatible with
// dlsym/GetProcAddress.
namespace CAMatrix::Audit::Core {
extern "C" AuditStrategy* create_audit_strategy() noexcept
{
    try { return new CAMatrix::Audit::Strategies::DHTDynamicAuditStrategy(); }
    catch (...) { return nullptr; }
}

extern "C" void destroy_audit_strategy(AuditStrategy* p) noexcept
{
    delete p;
}
} // namespace CAMatrix::Audit::Core
