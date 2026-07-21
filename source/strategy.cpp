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

            // Parse optional seed from JSON rawInput
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

            // Extract blocks (required)
            req->blocks = inputMap->getRequired<std::shared_ptr<CAMatrix::Audit::Data::AuditBlockSource>>("blocks");

            // Extract fileId (required)
            if (auto fileId = inputMap->getOptional<std::string>("fileId")) {
                ext->fileId = *fileId;
            }

            if (ext->fileId.empty()) {
                throw std::runtime_error("GenerateTags requires 'fileId' in Custom data");
            }

            // Extract targetBlockIndices (optional): when set, only generate tags
            // for the specified 1-based global block indices
            if (auto indices = inputMap->getOptional<std::vector<std::size_t>>("targetBlockIndices")) {
                req->targetBlockIndices = *indices;
            }

            req->ext = ext;
            return std::make_shared<AuditRequestVariant>(req);
        }

        case AuditOperation::ChallengeGen: {
            auto req = std::make_shared<GenerateChallengesRequest>();
            auto ext = std::make_shared<DHTDynamicChallengeRequestExt>();

            // Parse challenge parameters from JSON rawInput
            const Json::Value root = rawInput.requireJson(op);

            bool hasBlockCount = false;
            if (root.isMember("blockCount") && root["blockCount"].isUInt64()) {
                ext->blockCount = static_cast<std::size_t>(root["blockCount"].asUInt64());
                hasBlockCount = true;
            }

            if (root.isMember("challengeCount") && root["challengeCount"].isUInt64()) {
                ext->challengeCount = static_cast<std::size_t>(root["challengeCount"].asUInt64());
            }

            if (root.isMember("usePseudoRandom") && root["usePseudoRandom"].isBool()) {
                ext->usePseudoRandom = root["usePseudoRandom"].asBool();
            }

            if (root.isMember("seed") && root["seed"].isUInt64()) {
                ext->seed = root["seed"].asUInt64();
            }

            // Parse fileId from JSON rawInput (required for stateStore queries)
            if (root.isMember("fileId") && root["fileId"].isString()) {
                ext->fileId = root["fileId"].asString();
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

            ext->blocks = inputMap->getRequired<std::shared_ptr<CAMatrix::Audit::Data::AuditBlockSource>>("blocks");
            ext->tags = inputMap->getRequired<std::shared_ptr<CAMatrix::Audit::Messages::Tags>>("tags");

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

            // Retrieve userPublicParams from context
            if (context.generateKeysResult) {
                ext->userPublicParams = std::dynamic_pointer_cast<DHTDynamicPublicParams>(
                    context.generateKeysResult->publicParams);
            }

            if (!ext->userPublicParams) {
                throw std::runtime_error("VerifyProofs requires DHTDynamic public params from context");
            }

            // Parse fileId from JSON rawInput
            const Json::Value root = rawInput.requireJson(op);

            if (root.isMember("fileId")) {
                std::string parsed;
                if (!RawInput::jsonValueToString(root["fileId"], parsed)) {
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

            // Parse maintenance parameters from JSON rawInput
            const Json::Value root = rawInput.requireJson(op);

            // Extract fileId (required)
            if (!root.isMember("fileId") || !root["fileId"].isString()) {
                throw std::runtime_error("Maintenance requires 'fileId' field");
            }
            ext->fileId = root["fileId"].asString();

            // Extract opType (required)
            if (!root.isMember("opType") || !root["opType"].isUInt()) {
                throw std::runtime_error("Maintenance requires 'opType' field");
            }
            ext->opType = static_cast<CAMatrix::Audit::Messages::MaintenanceOpType>(root["opType"].asUInt());

            // Extract blockIndices (optional)
            if (root.isMember("blockIndices") && root["blockIndices"].isArray()) {
                for (const auto& idx : root["blockIndices"]) {
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
