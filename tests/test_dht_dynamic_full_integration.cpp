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
 * @file test_dht_dynamic_full_integration.cpp
 * @brief Comprehensive DHTDynamic audit integration test (Engine-driven).
 * @details Tests the full DHTDynamic PDP audit pipeline:
 *          init (no-op) → keygen → tags → challenges → proofs → verify,
 *          plus maintenance operations (Update/Insert/Delete) and
 *          serialization roundtrip for all Result types.
 *
 *          Key differences from SM9 static:
 *          - Init is a no-op (no KGC)
 *          - KeyGen uses optional seed for deterministic testing
 *          - Challenge generation requires StateStore injection
 *          - Verify checks Θ == Λ (aggregate pairing, no individual BLS)
 *          - Maintenance operations modify StateStore
 *
 * Test Intent Summary:
 * - Validate DHTDynamic full workflow via Engine: init → keygen → tags →
 *   challenges → proofs → verify (with StateStore injection).
 * - Validate tamper detection by mutating proof material.
 * - Validate StateStore operations (addFile, getBlockMetadata, getBlockCount).
 * - Validate maintenance operations (Update, Insert, Delete).
 * - Validate serialization/deserialization roundtrip for all Result types.
 * - Validate AuditEngine::createArtifact() for all DHTDynamic artifact types.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-08
 */

// ── Engine interface ──
#include "ChordAuditMatrixLib/interfaces/audit/engine.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/raw_input.h"
#include "ChordAuditMatrixLib/interfaces/audit/operation_context.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/algorithm_params.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/request_result.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/challenges.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/proves.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/tags.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/in_memory_tags.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/tag.h"

// ── DHTDynamic strategy & types ──
#include "DHTDynamicAuditStrategy/strategy.h"
#include "DHTDynamicAuditStrategy/common.h"
#include "DHTDynamicAuditStrategy/params.h"
#include "DHTDynamicAuditStrategy/challenges.h"
#include "DHTDynamicAuditStrategy/proves.h"
#include "DHTDynamicAuditStrategy/tags.h"
#include "DHTDynamicAuditStrategy/request_ext.h"
#include "DHTDynamicAuditStrategy/state_stores/dynamic_hash_table_state_store.h"
#include "DHTDynamicAuditStrategy/state_stores/versioned_block_metadata.h"
#include "DHTDynamicAuditStrategy/maintain_types.h"

// ── Block source ──
#include "ChordAuditMatrixLib/implementations/audit/data/memory_audit_block_source.h"
#include "ChordAuditMatrixLib/implementations/audit/data/memory_audit_unit.h"
#include "ChordAuditMatrixLib/implementations/audit/data/memory_audit_unit_producer.h"
#include "ChordAuditMatrixLib/implementations/audit/data/memory_audit_unit_sequence.h"
#include "ChordAuditMatrixLib/implementations/audit/data/memory_audit_block_packer.h"

#include <json/json.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <gtest/gtest.h>

// ═══════════════════════════════════════════════════════════════
// Namespace aliases
// ═══════════════════════════════════════════════════════════════

namespace AuditCore  = CAMatrix::Audit::Core;
namespace AuditMsg   = CAMatrix::Audit::Messages;
namespace AuditStrat = CAMatrix::Audit::Strategies;
namespace AuditData  = CAMatrix::Audit::Data;
namespace DHTD       = CAMatrix::Audit::Strategies::DHTDynamic;

// ═══════════════════════════════════════════════════════════════
// Test infrastructure
// ═══════════════════════════════════════════════════════════════

/// Create an audit block source with deterministic random data for testing.
/// @param seed  PRNG seed (0 = use random_device)
/// @param size  Total data size in bytes
/// @param blockSize  Size of each block
/// @return AuditBlockSourcePtr backed by MemoryAuditBlockPacker
static AuditData::AuditBlockSourcePtr
makeRandomBlockSource(std::uint32_t seed = 0, std::size_t size = 96, std::size_t blockSize = 16)
{
    std::vector<std::uint8_t> raw(size);

    if (seed == 0) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);
        for (auto& byte : raw) {
            byte = static_cast<std::uint8_t>(dist(gen));
        }
    } else {
        std::mt19937 gen(seed);
        std::uniform_int_distribution<int> dist(0, 255);
        for (auto& byte : raw) {
            byte = static_cast<std::uint8_t>(dist(gen));
        }
    }

    auto unit = std::make_shared<AuditData::MemoryAuditUnit>(std::move(raw));
    AuditData::MemoryAuditUnitProducer producer({unit}, AuditData::AuditDataBoundaryConstraint::Splittable);
    auto packer = std::make_shared<AuditData::MemoryAuditBlockPacker>(
        blockSize, producer.packingStrategy());
    auto sequence = producer.openSequence();
    packer->pack(*sequence);
    return packer;  // packer IS the AuditBlockSource
}

/// Create a fresh Engine instance with DHTDynamic strategy and inject StateStore.
static std::shared_ptr<AuditCore::AuditEngine> createDhtDynamicEngine(
    const std::shared_ptr<AuditStrat::DHTDynamic::DynamicHashTableStateStore>& stateStore)
{
    auto engine = AuditCore::AuditEngineFactory::createInstance();
    auto strategy = std::make_shared<AuditStrat::DHTDynamicAuditStrategy>();
    strategy->setStateStore(stateStore);
    engine->setStrategy(strategy);
    return engine;
}

/// Helper: write a Json::Value to string.
static std::string jsonToString(const ::Json::Value& v)
{
    return ::Json::FastWriter().write(v);
}

/// Helper: create a JSON RawInput.
static AuditMsg::RawInput jsonInput(const ::Json::Value& v)
{
    return AuditMsg::RawInput(std::make_shared<std::string>(jsonToString(v)));
}

// ═══════════════════════════════════════════════════════════════
// Serialization roundtrip helper
// ═══════════════════════════════════════════════════════════════

/// Verify serialization → deserialization → re-serialization for any Result type.
template <typename T>
void expectSerializationRoundtrip(const T &original)
{
    const auto serialized = original.serialize();
    EXPECT_FALSE(serialized.empty());

    T deserialized;
    if constexpr (std::is_same_v<T, AuditMsg::InitializeAlgorithmResult>) {
        deserialized.publicParams  = std::make_shared<DHTD::DHTDynamicAlgoPublicParams>();
        deserialized.privateParams = std::make_shared<DHTD::DHTDynamicAlgoPrivateParams>();
        deserialized.ext           = std::make_shared<DHTD::DHTDynamicAlgoInitResultExt>();
    } else if constexpr (std::is_same_v<T, AuditMsg::GenerateKeysResult>) {
        deserialized.publicParams  = std::make_shared<DHTD::DHTDynamicPublicParams>();
        deserialized.privateParams = std::make_shared<DHTD::DHTDynamicPrivateParams>();
    } else if constexpr (std::is_same_v<T, AuditMsg::GenerateChallengesResult>) {
        deserialized.challenges = std::make_shared<DHTD::DHTDynamicChallenges>();
        deserialized.ext         = std::make_shared<DHTD::DHTDynamicChallengeResultExt>();
    } else if constexpr (std::is_same_v<T, AuditMsg::GenerateProofsResult>) {
        deserialized.proves = std::make_shared<DHTD::DHTDynamicProves>();
        deserialized.ext    = std::make_shared<DHTD::DHTDynamicProveResultExt>();
    } else if constexpr (std::is_same_v<T, AuditMsg::VerifyProofsResult>) {
        deserialized.ext = std::make_shared<DHTD::DHTDynamicVerifyResultExt>();
    }

    EXPECT_TRUE(deserialized.deserialize(serialized));
    EXPECT_FALSE(deserialized.serialize().empty());
}

// ═══════════════════════════════════════════════════════════════
// Test 1: Artifact creation via Engine factory
// ═══════════════════════════════════════════════════════════════

TEST(DhtDynamicFull, ArtifactCreation)
{
    auto stateStore = std::make_shared<AuditStrat::DHTDynamic::DynamicHashTableStateStore>();
    auto engine = createDhtDynamicEngine(stateStore);

    // Challenges
    auto chalVar = engine->createArtifact(AuditCore::AuditArtifactKind::Challenges);
    auto chalPtr = std::get_if<AuditMsg::ChallengesPtr>(&chalVar);
    ASSERT_NE(chalPtr, nullptr);
    ASSERT_NE(*chalPtr, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicChallenges>(*chalPtr), nullptr);

    // Proves
    auto provVar = engine->createArtifact(AuditCore::AuditArtifactKind::Proves);
    auto provPtr = std::get_if<AuditMsg::ProvesPtr>(&provVar);
    ASSERT_NE(provPtr, nullptr);
    ASSERT_NE(*provPtr, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicProves>(*provPtr), nullptr);

    // Tags — created via InMemoryTags with DHTDynamicTag factory
    auto tags = std::make_shared<AuditMsg::InMemoryTags>(
        [] { return std::make_shared<DHTD::DHTDynamicTag>(); });
    EXPECT_NE(tags, nullptr);
    EXPECT_TRUE(tags->empty());

    // Individual Tag
    auto tVar = engine->createArtifact(AuditCore::AuditArtifactKind::Tag);
    auto tagPtr = std::get_if<AuditMsg::TagPtr>(&tVar);
    ASSERT_NE(tagPtr, nullptr);
    ASSERT_NE(*tagPtr, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicTag>(*tagPtr), nullptr);

    // Algorithm public/private params (no-op init → empty DHTDynamicAlgoPublicParams)
    auto algoPubVar = engine->createArtifact(AuditCore::AuditArtifactKind::AlgorithmPublicParams);
    auto algoPubPtr = std::get_if<std::shared_ptr<AuditMsg::AlgoPublicParams>>(&algoPubVar);
    ASSERT_NE(algoPubPtr, nullptr);
    ASSERT_NE(*algoPubPtr, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicAlgoPublicParams>(*algoPubPtr), nullptr);

    auto algoPrivVar = engine->createArtifact(AuditCore::AuditArtifactKind::AlgorithmPrivateParams);
    auto algoPrivPtr = std::get_if<std::shared_ptr<AuditMsg::AlgoPrivateParams>>(&algoPrivVar);
    ASSERT_NE(algoPrivPtr, nullptr);
    ASSERT_NE(*algoPrivPtr, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicAlgoPrivateParams>(*algoPrivPtr), nullptr);

    // User public/private params (from KeyGen → DHTDynamicPublicParams / DHTDynamicPrivateParams)
    auto userPubVar = engine->createArtifact(AuditCore::AuditArtifactKind::UserPublicParams);
    auto userPubPtr = std::get_if<std::shared_ptr<AuditMsg::AlgoPublicParams>>(&userPubVar);
    ASSERT_NE(userPubPtr, nullptr);
    ASSERT_NE(*userPubPtr, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicPublicParams>(*userPubPtr), nullptr);

    auto userPrivVar = engine->createArtifact(AuditCore::AuditArtifactKind::UserPrivateParams);
    auto userPrivPtr = std::get_if<std::shared_ptr<AuditMsg::AlgoPrivateParams>>(&userPrivVar);
    ASSERT_NE(userPrivPtr, nullptr);
    ASSERT_NE(*userPrivPtr, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicPrivateParams>(*userPrivPtr), nullptr);
}

// ═══════════════════════════════════════════════════════════════
// Test 2: Init (no-op) + KeyGen + serialization round-trip
// ═══════════════════════════════════════════════════════════════

TEST(DhtDynamicFull, InitKeygenAndSerialization)
{
    auto stateStore = std::make_shared<AuditStrat::DHTDynamic::DynamicHashTableStateStore>();
    auto engine = createDhtDynamicEngine(stateStore);
    AuditCore::AuditOperationContext ctx;

    // Init — empty RawInput (no-op for DHTDynamic)
    engine->initializeAlgorithm(AuditMsg::RawInput(), ctx);
    ASSERT_TRUE(ctx.initializeAlgorithmResult.has_value());
    EXPECT_TRUE(ctx.initializeAlgorithmResult->ok);
    EXPECT_NE(ctx.initializeAlgorithmResult->publicParams, nullptr);
    EXPECT_NE(ctx.initializeAlgorithmResult->privateParams, nullptr);

    // Init params must be DHTDynamicAlgo* (empty — no KGC).
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicAlgoPublicParams>(
                  ctx.initializeAlgorithmResult->publicParams),
              nullptr);

    // KeyGen — JSON with optional seed for deterministic testing.
    ::Json::Value keyJson;
    keyJson["seed"] = static_cast<::Json::UInt64>(42);
    engine->generateKeys(jsonInput(keyJson), ctx);
    ASSERT_TRUE(ctx.generateKeysResult.has_value());
    EXPECT_TRUE(ctx.generateKeysResult->ok);
    EXPECT_NE(ctx.generateKeysResult->publicParams, nullptr);
    EXPECT_NE(ctx.generateKeysResult->privateParams, nullptr);

    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicPublicParams>(
                  ctx.generateKeysResult->publicParams),
              nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicPrivateParams>(
                  ctx.generateKeysResult->privateParams),
              nullptr);

    // DHTDynamicAlgoPublicParams::do_serialize is intentionally empty (init is no-op),
    // so only key public params are expected to round-trip.
    const auto keyPubSerialized = ctx.generateKeysResult->publicParams->serialize();
    EXPECT_FALSE(keyPubSerialized.empty());

    auto restoredVar = engine->createArtifact(AuditCore::AuditArtifactKind::UserPublicParams);
    auto *ptr = std::get_if<std::shared_ptr<AuditMsg::AlgoPublicParams>>(&restoredVar);
    ASSERT_NE(ptr, nullptr);
    EXPECT_TRUE((*ptr)->deserialize(keyPubSerialized));
}

// ═══════════════════════════════════════════════════════════════
// Test 3: Full pipeline (init → keygen → tags → challenges → proofs → verify)
// ═══════════════════════════════════════════════════════════════

TEST(DhtDynamicFull, FullPipelineSuccess)
{
    const std::string testFileId = "test-file-dht-dynamic-pipeline";
    const std::size_t blockCount = 4;
    const std::size_t blockSize  = 256;

    auto stateStore = std::make_shared<AuditStrat::DHTDynamic::DynamicHashTableStateStore>();
    auto engine = createDhtDynamicEngine(stateStore);
    AuditCore::AuditOperationContext ctx;

    // ── Step 1: Initialize algorithm (no-op) ──
    engine->initializeAlgorithm(AuditMsg::RawInput(), ctx);
    ASSERT_TRUE(ctx.initializeAlgorithmResult.has_value());
    ASSERT_TRUE(ctx.initializeAlgorithmResult->ok);

    // ── Step 2: Generate keys ──
    ::Json::Value keyJson;
    keyJson["seed"] = static_cast<::Json::UInt64>(42);
    engine->generateKeys(jsonInput(keyJson), ctx);
    ASSERT_TRUE(ctx.generateKeysResult.has_value());
    ASSERT_TRUE(ctx.generateKeysResult->ok);

    // ── Step 3: Create test data blocks ──
    std::vector<std::vector<std::uint8_t>> blocks;
    for (std::size_t i = 0; i < blockCount; ++i) {
        std::vector<std::uint8_t> block(blockSize);
        for (std::size_t j = 0; j < blockSize; ++j) {
            block[j] = static_cast<std::uint8_t>((i * 31 + j * 17) & 0xFF);
        }
        blocks.push_back(std::move(block));
    }
    auto blockSource = std::make_shared<AuditData::MemoryAuditBlockSource>(blocks, blockSize, 0);
    EXPECT_EQ(blockSource->availableBlockCount(), blockCount);

    // ── Step 4: Register file and block metadata in StateStore BEFORE generateTags ──
    // generateTags reads version/timestamp from stateStore to compute H₁(fileId‖i‖v‖t).
    // If stateStore is not populated first, tags use defaults (v=1, t=0) which will
    // mismatch the stateStore metadata during verification.
    stateStore->addFile(testFileId);
    EXPECT_TRUE(stateStore->hasFile(testFileId));
    for (std::size_t i = 1; i <= blockCount; ++i) {
        stateStore->insertBlock(testFileId, i);
    }
    EXPECT_EQ(stateStore->getBlockCount(testFileId), blockCount);

    // ── Step 5: Generate tags (reads version/timestamp from stateStore) ──
    auto tagsDataMap = std::make_shared<AuditMsg::AuditDataMap>();
    tagsDataMap->emplace("blocks", AuditData::AuditBlockSourcePtr(blockSource));
    tagsDataMap->emplace("fileId", std::string(testFileId));
    engine->generateTags(AuditMsg::RawInput(tagsDataMap), ctx);
    ASSERT_TRUE(ctx.generateTagsResult.has_value());
    ASSERT_NE(ctx.generateTagsResult->tags, nullptr);
    EXPECT_EQ(ctx.generateTagsResult->tags->maxIndex(), blockCount);

    // ── Step 6: Generate challenges ──
    ::Json::Value chalJson;
    chalJson["fileId"]          = testFileId;
    chalJson["blockCount"]      = static_cast<::Json::UInt64>(blockCount);
    chalJson["challengeCount"]  = static_cast<::Json::UInt64>(2);
    chalJson["usePseudoRandom"] = true;
    chalJson["seed"]            = static_cast<::Json::UInt64>(42);
    engine->generateChallenges(jsonInput(chalJson), ctx);
    ASSERT_TRUE(ctx.generateChallengesResult.has_value());
    ASSERT_NE(ctx.generateChallengesResult->challenges, nullptr);

    auto dhtChallenges = std::dynamic_pointer_cast<DHTD::DHTDynamicChallenges>(
        ctx.generateChallengesResult->challenges);
    ASSERT_NE(dhtChallenges, nullptr);
    EXPECT_GT(dhtChallenges->challengeCount(), 0u);
    EXPECT_EQ(dhtChallenges->blockCount(), blockCount);

    // ── Step 7: Generate proofs ──
    auto proofsDataMap = std::make_shared<AuditMsg::AuditDataMap>();
    proofsDataMap->emplace("blocks", AuditData::AuditBlockSourcePtr(blockSource));
    proofsDataMap->emplace("tags", AuditMsg::TagsPtr(ctx.generateTagsResult->tags));
    engine->generateProofs(AuditMsg::RawInput(proofsDataMap), ctx);
    ASSERT_TRUE(ctx.generateProofsResult.has_value());
    ASSERT_NE(ctx.generateProofsResult->proves, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicProves>(
                  ctx.generateProofsResult->proves),
              nullptr);

    // ── Step 8: Verify proofs ──
    // DHTDynamic verify: Θ == Λ (aggregate pairing, no individual BLS verification)
    ::Json::Value verifyJson;
    verifyJson["fileId"] = testFileId;
    engine->verifyProofs(jsonInput(verifyJson), ctx);
    ASSERT_TRUE(ctx.verifyProofsResult.has_value());
    EXPECT_TRUE(ctx.verifyProofsResult->ok) << "reason: " << ctx.verifyProofsResult->reason;
}

// ═══════════════════════════════════════════════════════════════
// Test 4: Tamper detection (mutate proof, verify should fail)
// ═══════════════════════════════════════════════════════════════

TEST(DhtDynamicFull, TamperDetection)
{
    const std::string testFileId = "file-dht-tamper-001";

    auto stateStore = std::make_shared<AuditStrat::DHTDynamic::DynamicHashTableStateStore>();
    auto engine = createDhtDynamicEngine(stateStore);
    AuditCore::AuditOperationContext ctx;

    // ── Run full pipeline via Engine ──
    engine->initializeAlgorithm(AuditMsg::RawInput(), ctx);
    ASSERT_TRUE(ctx.initializeAlgorithmResult->ok);

    ::Json::Value keyJson;
    keyJson["seed"] = static_cast<::Json::UInt64>(20260708);
    engine->generateKeys(jsonInput(keyJson), ctx);
    ASSERT_TRUE(ctx.generateKeysResult->ok);

    auto blocks = makeRandomBlockSource(20260708, 96, 16);
    const std::size_t blockCount = blocks->availableBlockCount();
    ASSERT_GT(blockCount, 0u);

    // Register file in stateStore BEFORE generateTags so tags use correct version/timestamp
    stateStore->addFile(testFileId);
    for (std::size_t i = 1; i <= blockCount; ++i) {
        stateStore->insertBlock(testFileId, i);
    }

    auto tagsMap = std::make_shared<AuditMsg::AuditDataMap>();
    tagsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(blocks));
    tagsMap->emplace("fileId", std::string(testFileId));
    engine->generateTags(AuditMsg::RawInput(tagsMap), ctx);
    ASSERT_NE(ctx.generateTagsResult->tags, nullptr);

    ::Json::Value chalJson;
    chalJson["fileId"]          = testFileId;
    chalJson["blockCount"]      = static_cast<::Json::UInt64>(blockCount);
    chalJson["challengeCount"]  = static_cast<::Json::UInt64>(3);
    chalJson["usePseudoRandom"] = true;
    chalJson["seed"]            = static_cast<::Json::UInt64>(20260708);
    engine->generateChallenges(jsonInput(chalJson), ctx);
    ASSERT_NE(ctx.generateChallengesResult->challenges, nullptr);

    auto proofsMap = std::make_shared<AuditMsg::AuditDataMap>();
    proofsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(blocks));
    proofsMap->emplace("tags", AuditMsg::TagsPtr(ctx.generateTagsResult->tags));
    engine->generateProofs(AuditMsg::RawInput(proofsMap), ctx);
    ASSERT_NE(ctx.generateProofsResult->proves, nullptr);

    // ── Step 1: Verify original proof — should succeed ──
    ::Json::Value verifyJson;
    verifyJson["fileId"] = testFileId;
    engine->verifyProofs(jsonInput(verifyJson), ctx);
    ASSERT_TRUE(ctx.verifyProofsResult->ok);

    // ── Step 2: Tamper with the proof in context, then re-verify ──
    // Mutate Θ (theta) directly in the context's proof.
    // The Engine's verifyProofs reads from ctx.generateProofsResult,
    // so the next call will use the tampered proof.
    auto proves = std::dynamic_pointer_cast<DHTD::DHTDynamicProves>(
        ctx.generateProofsResult->proves);
    ASSERT_NE(proves, nullptr);

    // Flip a bit in theta to corrupt the proof
    auto thetaData = proves->theta().serialize();
    ASSERT_FALSE(thetaData.empty());
    thetaData[0] ^= 0x01;
    DHTD::SM9GTElement tamperedTheta;
    ASSERT_TRUE(tamperedTheta.deserialize(thetaData));
    proves->setTheta(tamperedTheta);

    // Re-verify via Engine — reads tampered proof from context
    engine->verifyProofs(jsonInput(verifyJson), ctx);
    EXPECT_FALSE(ctx.verifyProofsResult->ok);
}

// ═══════════════════════════════════════════════════════════════
// Test 5: StateStore operations
// ═══════════════════════════════════════════════════════════════

TEST(DhtDynamicFull, StateStoreOperations)
{
    auto stateStore = std::make_shared<AuditStrat::DHTDynamic::DynamicHashTableStateStore>();

    const std::string fileId = "file-state-store-test";
    const std::size_t blockCount = 10;

    // ── addFile ──
    stateStore->addFile(fileId);
    EXPECT_TRUE(stateStore->hasFile(fileId));
    EXPECT_EQ(stateStore->getBlockCount(fileId), 0u);

    // ── insertBlock (add blocks to empty file) ──
    for (std::size_t i = 1; i <= blockCount; ++i) {
        stateStore->insertBlock(fileId, i);
    }
    EXPECT_EQ(stateStore->getBlockCount(fileId), blockCount);

    // ── getBlockMetadata ──
    // blockIndex is 1-based
    for (std::size_t i = 0; i < blockCount; ++i) {
        auto meta = stateStore->getBlockMetadata(fileId, i + 1);
        auto dhtMeta = std::dynamic_pointer_cast<AuditStrat::DHTDynamic::VersionedBlockMetadata>(meta);
        ASSERT_NE(dhtMeta, nullptr);
        EXPECT_EQ(dhtMeta->version, 1u);
    }

    // ── modifyBlock (bump version) ──
    // modifyBlock now internally calls bump() which increments version and refreshes timestamp
    stateStore->modifyBlock(fileId, 1); // blockIndex is 1-based
    auto meta0 = stateStore->getBlockMetadata(fileId, 1);
        auto dhtMeta0 = std::dynamic_pointer_cast<AuditStrat::DHTDynamic::VersionedBlockMetadata>(meta0);
    ASSERT_NE(dhtMeta0, nullptr);
    EXPECT_EQ(dhtMeta0->version, 2u); // bumped from 1
    EXPECT_GT(dhtMeta0->timestamp, 0u);

    // ── insertBlock ──
    stateStore->insertBlock(fileId, 11); // blockIndex 1-based, insert after block 10
    EXPECT_EQ(stateStore->getBlockCount(fileId), blockCount + 1);
    // Verify inserted block exists (no throw).
    stateStore->getBlockMetadata(fileId, 11);

    // ── deleteBlock ──
    stateStore->deleteBlock(fileId, 11); // blockIndex is 1-based
    EXPECT_EQ(stateStore->getBlockCount(fileId), blockCount);

    // ── removeFile ──
    stateStore->removeFile(fileId);
    EXPECT_FALSE(stateStore->hasFile(fileId));
}

// ═══════════════════════════════════════════════════════════════
// Test 6: Maintenance operations (Update, Insert, Delete)
// ═══════════════════════════════════════════════════════════════

TEST(DhtDynamicFull, MaintenanceOperations)
{
    const std::string testFileId = "file-maint-test";
    const std::size_t blockCount = 4;
    const std::size_t blockSize  = 256;

    auto stateStore = std::make_shared<AuditStrat::DHTDynamic::DynamicHashTableStateStore>();
    auto engine = createDhtDynamicEngine(stateStore);
    AuditCore::AuditOperationContext ctx;

    // ── Setup: init → keygen → StateStore → tags ──
    engine->initializeAlgorithm(AuditMsg::RawInput(), ctx);
    EXPECT_TRUE(ctx.initializeAlgorithmResult->ok) << "maint: init succeeded";

    ::Json::Value keyJson;
    keyJson["seed"] = static_cast<::Json::UInt64>(123);
    engine->generateKeys(jsonInput(keyJson), ctx);
    EXPECT_TRUE(ctx.generateKeysResult->ok) << "maint: keygen succeeded";

    // Create initial blocks (4 blocks, deterministic content)
    // Block content formula: block[i][j] = (i * 31 + j * 17) & 0xFF
    std::vector<std::vector<std::uint8_t>> blocks;
    for (std::size_t i = 0; i < blockCount; ++i) {
        std::vector<std::uint8_t> block(blockSize);
        for (std::size_t j = 0; j < blockSize; ++j) {
            block[j] = static_cast<std::uint8_t>((i * 31 + j * 17) & 0xFF);
        }
        blocks.push_back(std::move(block));
    }
    auto blockSource = std::make_shared<AuditData::MemoryAuditBlockSource>(blocks, blockSize, 0);

    // Register file and block metadata in StateStore BEFORE generateTags.
    // generateTags reads version/timestamp from StateStore to compute
    // H₁(fileId‖blockIndex‖version‖timestamp).
    stateStore->addFile(testFileId);
    for (std::size_t i = 1; i <= blockCount; ++i) {
        stateStore->insertBlock(testFileId, i);
    }
    EXPECT_TRUE(stateStore->hasFile(testFileId)) << "maint: file added to stateStore";
    EXPECT_TRUE(stateStore->getBlockCount(testFileId) == blockCount) << "maint: stateStore block count matches";

    // Generate tags (reads version/timestamp from stateStore)
    // globalBlockStartIndex=0 → tags stored at indices 0,1,2,3 (blockIndex 1,2,3,4)
    auto tagsDataMap = std::make_shared<AuditMsg::AuditDataMap>();
    tagsDataMap->emplace("blocks", AuditData::AuditBlockSourcePtr(blockSource));
    tagsDataMap->emplace("fileId", std::string(testFileId));
    engine->generateTags(AuditMsg::RawInput(tagsDataMap), ctx);
    EXPECT_TRUE(ctx.generateTagsResult->tags != nullptr) << "maint: tags generated";

    // Save the full tags collection — we will maintain it across operations
    auto allTags = ctx.generateTagsResult->tags;

    // ── Test Update operation ──
    // Design: maintain(Update) bumps StateStore version → generateTags reads
    // new version → merge new tags into allTags → challenge→prove→verify.
    // Order matters: maintain MUST happen before generateTags, because
    // generateTags reads version from StateStore.
    {
        // Verify initial version is 1
        auto meta0 = stateStore->getBlockMetadata(testFileId, 1);
        auto dhtMeta = std::dynamic_pointer_cast<::CAMatrix::Audit::Strategies::DHTDynamic::VersionedBlockMetadata>(meta0);
        EXPECT_TRUE(dhtMeta != nullptr && dhtMeta->version == 1) << "maint-update: initial version is 1";

        // Step 1: maintain(Update) — bumps version in StateStore
        ::Json::Value updateJson;
        updateJson["fileId"] = testFileId;
        updateJson["opType"] = static_cast<::Json::UInt64>(0);  // Update = 0
        updateJson["blockIndices"] = ::Json::Value(::Json::arrayValue);
        updateJson["blockIndices"][0] = static_cast<::Json::UInt64>(1);
        updateJson["blockIndices"][1] = static_cast<::Json::UInt64>(2);

        engine->maintain(jsonInput(updateJson), ctx);
        EXPECT_TRUE(ctx.maintainResult.has_value()) << "maint-update: result present";
        // maintenance() only updates StateStore; tags is nullptr (caller manages tags)

        // Verify version bumped
        auto updatedMeta = stateStore->getBlockMetadata(testFileId, 1);
        auto updatedDhtMeta = std::dynamic_pointer_cast<::CAMatrix::Audit::Strategies::DHTDynamic::VersionedBlockMetadata>(updatedMeta);
        EXPECT_TRUE(updatedDhtMeta != nullptr && updatedDhtMeta->version == 2) << "maint-update: version bumped from 1 to 2";

        // Step 2: generateTags for updated blocks (content changed)
        // σ_i = [a]·(H_i + Σ[segment_j]·u) is content-dependent, so tags MUST
        // be regenerated when block content changes.
        // We provide the FULL 4-block source and specify targetBlockIndices={1,2}
        // so only blocks 1 and 2 get new tags. This mirrors production usage where
        // the caller provides the full file but only needs tags for changed blocks.
        std::vector<std::vector<std::uint8_t>> allBlocksForUpdate;
        // Blocks 1,2: updated content — block[i][j] = (i * 53 + j * 97 + 200) & 0xFF
        for (std::size_t i = 0; i < 2; ++i) {
            std::vector<std::uint8_t> block(blockSize);
            for (std::size_t j = 0; j < blockSize; ++j) {
                block[j] = static_cast<std::uint8_t>((i * 53 + j * 97 + 200) & 0xFF);
            }
            allBlocksForUpdate.push_back(std::move(block));
        }
        // Blocks 3,4: original content — block[i][j] = (i * 31 + j * 17) & 0xFF
        for (std::size_t i = 2; i < blockCount; ++i) {
            std::vector<std::uint8_t> block(blockSize);
            for (std::size_t j = 0; j < blockSize; ++j) {
                block[j] = static_cast<std::uint8_t>((i * 31 + j * 17) & 0xFF);
            }
            allBlocksForUpdate.push_back(std::move(block));
        }
        auto fullBlockSource4 = std::make_shared<AuditData::MemoryAuditBlockSource>(
            allBlocksForUpdate, blockSize, 0);

        AuditCore::AuditOperationContext updateCtx;
        updateCtx.initializeAlgorithmResult = ctx.initializeAlgorithmResult;
        updateCtx.generateKeysResult = ctx.generateKeysResult;

        auto updateTagsMap = std::make_shared<AuditMsg::AuditDataMap>();
        updateTagsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(fullBlockSource4));
        updateTagsMap->emplace("fileId", std::string(testFileId));
        updateTagsMap->emplace("targetBlockIndices", std::vector<std::size_t>{1, 2});
        engine->generateTags(AuditMsg::RawInput(updateTagsMap), updateCtx);
        EXPECT_TRUE(updateCtx.generateTagsResult->tags != nullptr) << "maint-update: new tags generated";

        // Step 3: Merge new tags into allTags using set()
        // targetBlockIndices={1,2} → tags at global indices 0,1 (= blockIndex - 1)
        // Save old tags first so we can verify that stale tags fail verification.
        auto oldTag0 = allTags->getByIndex(0);
        auto oldTag1 = allTags->getByIndex(1);
        allTags->set(0, updateCtx.generateTagsResult->tags->getByIndex(0));
        allTags->set(1, updateCtx.generateTagsResult->tags->getByIndex(1));

        // Step 4: Post-maintenance audit verification with NEW tags
        // Reuse fullBlockSource4 (4 blocks: 1,2 updated; 3,4 original)

        // Set context tags for challenge generation
        ctx.generateTagsResult->tags = allTags;

        ::Json::Value chalJson;
        chalJson["fileId"]          = testFileId;
        chalJson["blockCount"]      = static_cast<::Json::UInt64>(blockCount);
        chalJson["challengeCount"]  = static_cast<::Json::UInt64>(2);
        chalJson["usePseudoRandom"] = true;
        chalJson["seed"]            = static_cast<::Json::UInt64>(999);
        engine->generateChallenges(jsonInput(chalJson), ctx);
        EXPECT_TRUE(ctx.generateChallengesResult->challenges != nullptr) << "maint-update: challenges generated";

        auto proofsMap = std::make_shared<AuditMsg::AuditDataMap>();
        proofsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(fullBlockSource4));
        proofsMap->emplace("tags", AuditMsg::TagsPtr(allTags));
        engine->generateProofs(AuditMsg::RawInput(proofsMap), ctx);
        EXPECT_TRUE(ctx.generateProofsResult->proves != nullptr) << "maint-update: proofs generated";

        ::Json::Value verifyJson;
        verifyJson["fileId"] = testFileId;
        engine->verifyProofs(jsonInput(verifyJson), ctx);
        EXPECT_TRUE(ctx.verifyProofsResult.has_value()) << "maint-update: verify result present";
        EXPECT_TRUE(ctx.verifyProofsResult->ok) << "maint-update: post-update verification SUCCEEDED";
        if (!ctx.verifyProofsResult->ok) {
        }

        // Step 5: Verify that STALE (old) tags fail verification
        // Replace blocks 1,2 tags with the old (pre-update) versions and
        // verify that the audit fails — proving tags are content-dependent.
        allTags->set(0, oldTag0);
        allTags->set(1, oldTag1);
        ctx.generateTagsResult->tags = allTags;

        engine->generateChallenges(jsonInput(chalJson), ctx);
        EXPECT_TRUE(ctx.generateChallengesResult->challenges != nullptr) << "maint-update: stale-tag challenges generated";

        auto staleProofsMap = std::make_shared<AuditMsg::AuditDataMap>();
        staleProofsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(fullBlockSource4));
        staleProofsMap->emplace("tags", AuditMsg::TagsPtr(allTags));
        engine->generateProofs(AuditMsg::RawInput(staleProofsMap), ctx);
        EXPECT_TRUE(ctx.generateProofsResult->proves != nullptr) << "maint-update: stale-tag proofs generated";

        engine->verifyProofs(jsonInput(verifyJson), ctx);
        EXPECT_TRUE(ctx.verifyProofsResult.has_value()) << "maint-update: stale-tag verify result present";
        EXPECT_TRUE(!ctx.verifyProofsResult->ok) << "maint-update: stale tags MUST fail verification";
        if (ctx.verifyProofsResult->ok) {
        }

        // Restore new tags for subsequent operations (Insert/Delete)
        allTags->set(0, updateCtx.generateTagsResult->tags->getByIndex(0));
        allTags->set(1, updateCtx.generateTagsResult->tags->getByIndex(1));
    }

    // ── Test Insert operation ──
    // Design: maintain(Insert) → generateTags for new blocks with
    // globalBlockStartIndex=4 → merge new tags at global indices →
    // challenge→prove→verify with full 6-block collection.
    {
        // Step 1: maintain(Insert) — inserts BlockMetadata in StateStore
        ::Json::Value insertJson;
        insertJson["fileId"] = testFileId;
        insertJson["opType"] = static_cast<::Json::UInt64>(1);  // Insert = 1
        insertJson["blockIndices"] = ::Json::Value(::Json::arrayValue);
        insertJson["blockIndices"][0] = static_cast<::Json::UInt64>(5);
        insertJson["blockIndices"][1] = static_cast<::Json::UInt64>(6);

        engine->maintain(jsonInput(insertJson), ctx);
        EXPECT_TRUE(ctx.maintainResult.has_value()) << "maint-insert: result present";
        EXPECT_TRUE(stateStore->getBlockCount(testFileId) == blockCount + 2) << "maint-insert: block count increased after insert";

        // Step 2: generateTags for new blocks with targetBlockIndices={5,6}
        // We provide the FULL 6-block source and specify targetBlockIndices={5,6}
        // so only blocks 5 and 6 get new tags. This mirrors production usage where
        // the caller provides the full file but only needs tags for inserted blocks.
        // Block content: blocks 1,2 updated; blocks 3,4 original; blocks 5,6 inserted.
        std::vector<std::vector<std::uint8_t>> allBlocksForInsert;
        // Blocks 1,2: updated content
        for (std::size_t i = 0; i < 2; ++i) {
            std::vector<std::uint8_t> block(blockSize);
            for (std::size_t j = 0; j < blockSize; ++j) {
                block[j] = static_cast<std::uint8_t>((i * 53 + j * 97 + 200) & 0xFF);
            }
            allBlocksForInsert.push_back(std::move(block));
        }
        // Blocks 3,4: original content
        for (std::size_t i = 2; i < blockCount; ++i) {
            std::vector<std::uint8_t> block(blockSize);
            for (std::size_t j = 0; j < blockSize; ++j) {
                block[j] = static_cast<std::uint8_t>((i * 31 + j * 17) & 0xFF);
            }
            allBlocksForInsert.push_back(std::move(block));
        }
        // Blocks 5,6: inserted content
        for (std::size_t i = 0; i < 2; ++i) {
            std::vector<std::uint8_t> block(blockSize);
            for (std::size_t j = 0; j < blockSize; ++j) {
                block[j] = static_cast<std::uint8_t>(((4 + i) * 31 + j * 17) & 0xFF);
            }
            allBlocksForInsert.push_back(std::move(block));
        }
        auto fullBlockSource6 = std::make_shared<AuditData::MemoryAuditBlockSource>(
            allBlocksForInsert, blockSize, 0);

        AuditCore::AuditOperationContext insertCtx;
        insertCtx.initializeAlgorithmResult = ctx.initializeAlgorithmResult;
        insertCtx.generateKeysResult = ctx.generateKeysResult;

        auto insertTagsMap = std::make_shared<AuditMsg::AuditDataMap>();
        insertTagsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(fullBlockSource6));
        insertTagsMap->emplace("fileId", std::string(testFileId));
        insertTagsMap->emplace("targetBlockIndices", std::vector<std::size_t>{5, 6});
        engine->generateTags(AuditMsg::RawInput(insertTagsMap), insertCtx);
        EXPECT_TRUE(insertCtx.generateTagsResult->tags != nullptr) << "maint-insert: new tags generated";

        // Step 3: Merge new tags into allTags using set()
        // targetBlockIndices={5,6} → tags at global indices 4,5 (= blockIndex - 1)
        allTags->set(4, insertCtx.generateTagsResult->tags->getByIndex(4));
        allTags->set(5, insertCtx.generateTagsResult->tags->getByIndex(5));

        // Step 4: Post-maintenance audit verification with NEW tags
        // Reuse fullBlockSource6 (6 blocks: 1,2 updated; 3,4 original; 5,6 inserted)

        // Set context tags for challenge generation
        ctx.generateTagsResult->tags = allTags;

        ::Json::Value chalJson;
        chalJson["fileId"]          = testFileId;
        chalJson["blockCount"]      = static_cast<::Json::UInt64>(blockCount + 2);
        chalJson["challengeCount"]  = static_cast<::Json::UInt64>(2);
        chalJson["usePseudoRandom"] = true;
        chalJson["seed"]            = static_cast<::Json::UInt64>(888);
        engine->generateChallenges(jsonInput(chalJson), ctx);
        EXPECT_TRUE(ctx.generateChallengesResult->challenges != nullptr) << "maint-insert: challenges generated";

        auto proofsMap = std::make_shared<AuditMsg::AuditDataMap>();
        proofsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(fullBlockSource6));
        proofsMap->emplace("tags", AuditMsg::TagsPtr(allTags));
        engine->generateProofs(AuditMsg::RawInput(proofsMap), ctx);
        EXPECT_TRUE(ctx.generateProofsResult->proves != nullptr) << "maint-insert: proofs generated";

        ::Json::Value verifyJson;
        verifyJson["fileId"] = testFileId;
        engine->verifyProofs(jsonInput(verifyJson), ctx);
        EXPECT_TRUE(ctx.verifyProofsResult.has_value()) << "maint-insert: verify result present";
        EXPECT_TRUE(ctx.verifyProofsResult->ok) << "maint-insert: post-insert verification SUCCEEDED";
        if (!ctx.verifyProofsResult->ok) {
        }

        // Step 5: Verify that INCOMPLETE tags (missing blocks 5,6) fail verification.
        // Insert does NOT bump version on existing blocks 1-4, so their old tags
        // remain valid. The real integrity check is: a tag collection that lacks
        // the newly inserted blocks' tags cannot pass verification when challenged
        // over the full 6-block range, because generateProofs skips challenge
        // items whose blockIndex has no tag, producing an incomplete proof.
        // Use oldAllTags (only blocks 1-4) with blockCount=6 so challenges may
        // reference blocks 5,6 which have no tags in oldAllTags.
        auto oldAllTags = std::make_shared<AuditMsg::InMemoryTags>();
        for (std::size_t idx = 0; idx < allTags->maxIndex() + 1; ++idx) {
            if (allTags->contains(idx) && idx < 4) {  // only blocks 1-4 (0-based: 0-3)
                oldAllTags->set(idx, allTags->getByIndex(idx));
            }
        }

        ctx.generateTagsResult->tags = oldAllTags;  // only blocks 1-4, missing 5,6

        ::Json::Value incompleteChalJson;
        incompleteChalJson["fileId"]          = testFileId;
        incompleteChalJson["blockCount"]      = static_cast<::Json::UInt64>(blockCount + 2);  // 6 blocks
        incompleteChalJson["challengeCount"]  = static_cast<::Json::UInt64>(6);  // challenge all 6 blocks
        incompleteChalJson["usePseudoRandom"] = true;
        incompleteChalJson["seed"]            = static_cast<::Json::UInt64>(999);
        engine->generateChallenges(jsonInput(incompleteChalJson), ctx);
        EXPECT_TRUE(ctx.generateChallengesResult->challenges != nullptr) << "maint-insert: incomplete-tag challenges generated";

        auto incompleteProofsMap = std::make_shared<AuditMsg::AuditDataMap>();
        incompleteProofsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(fullBlockSource6));
        incompleteProofsMap->emplace("tags", AuditMsg::TagsPtr(oldAllTags));
        engine->generateProofs(AuditMsg::RawInput(incompleteProofsMap), ctx);
        EXPECT_TRUE(ctx.generateProofsResult->proves != nullptr) << "maint-insert: incomplete-tag proofs generated";

        engine->verifyProofs(jsonInput(verifyJson), ctx);
        EXPECT_TRUE(ctx.verifyProofsResult.has_value()) << "maint-insert: incomplete-tag verify result present";
        EXPECT_TRUE(!ctx.verifyProofsResult->ok) << "maint-insert: incomplete tags (missing blocks 5,6) MUST fail verification";
        if (ctx.verifyProofsResult->ok) {
        }

        // Restore full tags (including blocks 5,6) for subsequent operations (Delete)
        ctx.generateTagsResult->tags = allTags;
    }

    // ── Test Delete operation ──
    // Design: maintain(Delete) → extract surviving tags from allTags into a
    // new InMemoryTags (simulates database remove) → challenge→prove→verify.
    // In production, tag removal is a database operation. In this in-memory
    // test, we create a new InMemoryTags and copy only the surviving tags
    // (all except the deleted block's tag) from the existing collection.
    {
        // Step 1: maintain(Delete) — removes block 6 from StateStore
        std::size_t countBefore = stateStore->getBlockCount(testFileId);

        ::Json::Value deleteJson;
        deleteJson["fileId"] = testFileId;
        deleteJson["opType"] = static_cast<::Json::UInt64>(2);  // Delete = 2
        deleteJson["blockIndices"] = ::Json::Value(::Json::arrayValue);
        deleteJson["blockIndices"][0] = static_cast<::Json::UInt64>(6);

        engine->maintain(jsonInput(deleteJson), ctx);
        EXPECT_TRUE(ctx.maintainResult.has_value()) << "maint-delete: result present";
        EXPECT_TRUE(stateStore->getBlockCount(testFileId) < countBefore) << "maint-delete: block count decreased after delete";

        // Step 2: Extract surviving tags into a new InMemoryTags
        // Block 6 was deleted → its tag is at index 5 (= blockIndex 6 - 1).
        // Copy all tags except index 5 into a new collection.
        // This simulates the production database operation of removing a tag.
        // No need to create new Tag objects — we already have shared_ptr<Tag>
        // to each existing tag, so we just copy the pointers.
        auto remainingTags = std::make_shared<AuditMsg::InMemoryTags>();
        for (std::size_t idx = 0; idx < allTags->maxIndex(); ++idx) {
            if (idx != 5 && allTags->contains(idx)) {
                remainingTags->set(idx, allTags->getByIndex(idx));
            }
        }
        EXPECT_TRUE(remainingTags->size() == 5) << "maint-delete: surviving tags count is 5";

        // Replace allTags with the surviving tags collection
        allTags = remainingTags;
        ctx.generateTagsResult->tags = allTags;

        // Step 3: Build remaining block source for challenge→prove→verify
        // Remaining blocks: 1(updated,v2), 2(updated,v2), 3(orig,v1),
        //                   4(orig,v1), 5(inserted,v1)
        std::vector<std::vector<std::uint8_t>> remainingBlocks;
        // Blocks 1,2: updated content
        for (std::size_t i = 0; i < 2; ++i) {
            std::vector<std::uint8_t> block(blockSize);
            for (std::size_t j = 0; j < blockSize; ++j) {
                block[j] = static_cast<std::uint8_t>((i * 53 + j * 97 + 200) & 0xFF);
            }
            remainingBlocks.push_back(std::move(block));
        }
        // Blocks 3,4: original content
        for (std::size_t i = 2; i < blockCount; ++i) {
            std::vector<std::uint8_t> block(blockSize);
            for (std::size_t j = 0; j < blockSize; ++j) {
                block[j] = static_cast<std::uint8_t>((i * 31 + j * 17) & 0xFF);
            }
            remainingBlocks.push_back(std::move(block));
        }
        // Block 5: inserted content
        {
            std::vector<std::uint8_t> block(blockSize);
            for (std::size_t j = 0; j < blockSize; ++j) {
                block[j] = static_cast<std::uint8_t>((4 * 31 + j * 17) & 0xFF);
            }
            remainingBlocks.push_back(std::move(block));
        }
        auto remainingBlockSource = std::make_shared<AuditData::MemoryAuditBlockSource>(
            remainingBlocks, blockSize, 0);

        // Step 4: Post-maintenance audit verification
        ::Json::Value chalJson;
        chalJson["fileId"]          = testFileId;
        chalJson["blockCount"]      = static_cast<::Json::UInt64>(5);
        chalJson["challengeCount"]  = static_cast<::Json::UInt64>(2);
        chalJson["usePseudoRandom"] = true;
        chalJson["seed"]            = static_cast<::Json::UInt64>(777);
        engine->generateChallenges(jsonInput(chalJson), ctx);
        EXPECT_TRUE(ctx.generateChallengesResult->challenges != nullptr) << "maint-delete: challenges generated";

        auto proofsMap = std::make_shared<AuditMsg::AuditDataMap>();
        proofsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(remainingBlockSource));
        proofsMap->emplace("tags", AuditMsg::TagsPtr(allTags));
        engine->generateProofs(AuditMsg::RawInput(proofsMap), ctx);
        EXPECT_TRUE(ctx.generateProofsResult->proves != nullptr) << "maint-delete: proofs generated";

        ::Json::Value verifyJson;
        verifyJson["fileId"] = testFileId;
        engine->verifyProofs(jsonInput(verifyJson), ctx);
        EXPECT_TRUE(ctx.verifyProofsResult.has_value()) << "maint-delete: verify result present";
        EXPECT_TRUE(ctx.verifyProofsResult->ok) << "maint-delete: post-delete verification SUCCEEDED";
        if (!ctx.verifyProofsResult->ok) {
        }
    }

}

// ═══════════════════════════════════════════════════════════════
// Test 7: Result serialization roundtrip for all Result types
// ═══════════════════════════════════════════════════════════════

TEST(DhtDynamicFull, ResultSerializationRoundtrip)
{
    const std::string testFileId = "test_file_dhtd_ser";
    const std::size_t blockCount = 4;
    const std::size_t blockSize  = 256;

    auto stateStore = std::make_shared<AuditStrat::DHTDynamic::DynamicHashTableStateStore>();
    auto engine = createDhtDynamicEngine(stateStore);
    AuditCore::AuditOperationContext ctx;

    // ── Step 1: Init ──
    engine->initializeAlgorithm(AuditMsg::RawInput(), ctx);
    EXPECT_TRUE(ctx.initializeAlgorithmResult->ok) << "ser: init succeeded";
    expectSerializationRoundtrip(*ctx.initializeAlgorithmResult);

    // ── Step 2: KeyGen ──
    ::Json::Value keyJson;
    keyJson["seed"] = static_cast<::Json::UInt64>(42);
    engine->generateKeys(jsonInput(keyJson), ctx);
    EXPECT_TRUE(ctx.generateKeysResult->ok) << "ser: keygen succeeded";
    expectSerializationRoundtrip(*ctx.generateKeysResult);

    // ── Step 3: Tags ──
    std::vector<std::vector<std::uint8_t>> blocks;
    for (std::size_t i = 0; i < blockCount; ++i) {
        std::vector<std::uint8_t> block(blockSize);
        for (std::size_t j = 0; j < blockSize; ++j) {
            block[j] = static_cast<std::uint8_t>((i * 31 + j * 17) & 0xFF);
        }
        blocks.push_back(std::move(block));
    }
    auto blockSource = std::make_shared<AuditData::MemoryAuditBlockSource>(blocks, blockSize, 0);

    // Register file in stateStore BEFORE generateTags so tags use correct version/timestamp
    stateStore->addFile(testFileId);
    for (std::size_t i = 1; i <= blockCount; ++i) {
        stateStore->insertBlock(testFileId, i);
    }

    auto tagsMap = std::make_shared<AuditMsg::AuditDataMap>();
    tagsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(blockSource));
    tagsMap->emplace("fileId", std::string(testFileId));
    engine->generateTags(AuditMsg::RawInput(tagsMap), ctx);
    EXPECT_TRUE(ctx.generateTagsResult->tags != nullptr) << "ser: tags generated";
    // Note: GenerateTagsResult is not CryptoSerializable, skip roundtrip test

    // ── Step 4: Challenges ──

    ::Json::Value chalJson;
    chalJson["fileId"]          = testFileId;
    chalJson["blockCount"]      = static_cast<::Json::UInt64>(blockCount);
    chalJson["challengeCount"]  = static_cast<::Json::UInt64>(2);
    chalJson["usePseudoRandom"] = true;
    chalJson["seed"]            = static_cast<::Json::UInt64>(42);
    engine->generateChallenges(jsonInput(chalJson), ctx);
    EXPECT_TRUE(ctx.generateChallengesResult->challenges != nullptr) << "ser: challenges generated";
    expectSerializationRoundtrip(*ctx.generateChallengesResult);

    // ── Step 5: Proofs ──
    auto proofsMap = std::make_shared<AuditMsg::AuditDataMap>();
    proofsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(blockSource));
    proofsMap->emplace("tags", AuditMsg::TagsPtr(ctx.generateTagsResult->tags));
    engine->generateProofs(AuditMsg::RawInput(proofsMap), ctx);
    EXPECT_TRUE(ctx.generateProofsResult->proves != nullptr) << "ser: proofs generated";
    expectSerializationRoundtrip(*ctx.generateProofsResult);

    // ── Step 6: Verify ──
    ::Json::Value verifyJson;
    verifyJson["fileId"] = testFileId;
    engine->verifyProofs(jsonInput(verifyJson), ctx);
    EXPECT_TRUE(ctx.verifyProofsResult->ok) << "ser: verification succeeded";
    expectSerializationRoundtrip(*ctx.verifyProofsResult);

}

// ═══════════════════════════════════════════════════════════════
// (main provided by gtest_main)
// ═══════════════════════════════════════════════════════════════