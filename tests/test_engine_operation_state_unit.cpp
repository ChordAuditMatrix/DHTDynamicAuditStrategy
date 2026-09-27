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
 * @file test_engine_operation_state_unit.cpp
 * @brief Tests that AuditEngine reads its strategy and StateStore per operation.
 * @details AuditEngine is a stateless facade: it keeps neither a strategy nor a
 *          StateStore. Every operation takes them from its own
 *          AuditOperationContext, so two calls on the same engine can run with
 *          different strategies and different stores.
 *
 * Test Intent Summary:
 * - Every engine operation rejects a context without a strategy.
 * - The engine does not retain the strategy of a previous call.
 * - Each call executes with the strategy bound to its own context.
 * - Each call reads and writes the StateStore bound to its own context.
 * - DHTDynamic degradation contract: challenge generation without a usable
 *   store yields no challenges instead of crashing.
 * - createStateStore() builds a fresh store per call and rejects null/static
 *   strategies; maintain() rejects static strategies.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-09-27
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "ChordAuditMatrixLib/interfaces/audit/engine.h"
#include "ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h"
#include "ChordAuditMatrixLib/interfaces/audit/static_strategy.h"
#include "ChordAuditMatrixLib/interfaces/audit/artifact_factory.h"
#include "ChordAuditMatrixLib/interfaces/audit/state_stores/dynamic_pdp_state_store.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/raw_input.h"
#include "ChordAuditMatrixLib/implementations/audit/data/memory_audit_block_source.h"
#include "DHTDynamicAuditStrategy/state_stores/dynamic_hash_table_state_store.h"
#include "DHTDynamicAuditStrategy/state_stores/versioned_block_metadata.h"
#include "DHTDynamicAuditStrategy/challenges.h"
#include "DHTDynamicAuditStrategy/strategy.h"

#include <json/json.h>
#include <gtest/gtest.h>

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace AuditCore  = CAMatrix::Audit::Core;
namespace AuditMsg   = CAMatrix::Audit::Messages;
namespace AuditData  = CAMatrix::Audit::Data;
namespace DHTD       = CAMatrix::Audit::Strategies::DHTDynamic;

using CAMatrix::Audit::Core::AuditEngine;
using CAMatrix::Audit::Core::AuditEngineFactory;
using CAMatrix::Audit::Core::AuditOperationContext;
using CAMatrix::Audit::Strategies::DHTDynamicAuditStrategy;

namespace {

/// Assert that `expr` throws std::runtime_error whose message contains `needle`.
::testing::AssertionResult throwsRuntimeErrorContaining(const std::function<void()>& expr,
                                                        const std::string& needle)
{
    try {
        expr();
        return ::testing::AssertionFailure()
            << "expected std::runtime_error containing \"" << needle
            << "\", but no exception was thrown";
    } catch (const std::runtime_error& e) {
        if (std::string(e.what()).find(needle) == std::string::npos) {
            return ::testing::AssertionFailure()
                << "exception message does not contain \"" << needle << "\": " << e.what();
        }
        return ::testing::AssertionSuccess();
    } catch (const std::exception& e) {
        return ::testing::AssertionFailure()
            << "expected std::runtime_error, got " << typeid(e).name() << ": " << e.what();
    }
}

/// Minimal artifact factory for the static strategy stub.
class StubArtifactFactory final : public AuditCore::AuditStrategyArtifactFactory {
public:
    AuditCore::AuditArtifactVariant createArtifact(AuditCore::AuditArtifactKind) const override
    {
        throw std::runtime_error("StubArtifactFactory: not implemented");
    }
};

/// Minimal static strategy: only used to prove that engine operations pick the
/// strategy carried by the operation context (and reject non-dynamic ones for
/// maintenance / state-store creation).
class StubStaticStrategy final : public AuditCore::StaticAuditStrategy {
public:
    CAMatrix::Audit::Messages::Capabilities caps() const override { return {}; }
    void setAlgorithm(CAMatrix::Crypto::CryptoGeneralAlgorithmPtr) override {}
    CAMatrix::Audit::Messages::InitializeAlgorithmResult initializeAlgorithm(
        const CAMatrix::Audit::Messages::InitializeAlgorithmRequest&) override { return {}; }
    CAMatrix::Audit::Messages::GenerateKeysResult generateKeys(
        const CAMatrix::Audit::Messages::GenerateKeysRequest&) override { return {}; }
    CAMatrix::Audit::Messages::GenerateTagsResult generateTags(
        const CAMatrix::Audit::Messages::GenerateTagsRequest&) override { return {}; }
    CAMatrix::Audit::Messages::GenerateChallengesResult generateChallenges(
        const CAMatrix::Audit::Messages::GenerateChallengesRequest&) override { return {}; }
    CAMatrix::Audit::Messages::GenerateProofsResult generateProofs(
        const CAMatrix::Audit::Messages::GenerateProofsRequest&) override { return {}; }
    CAMatrix::Audit::Messages::VerifyProofsResult verifyProofs(
        const CAMatrix::Audit::Messages::VerifyProofsRequest&) override { return {}; }
    CAMatrix::Audit::Messages::AuditRequestVariantPtr createRequest(
        AuditCore::AuditOperation,
        const AuditOperationContext&,
        const CAMatrix::Audit::Messages::RawInput& = CAMatrix::Audit::Messages::RawInput()) override
    {
        return nullptr;
    }
    std::string algorithmType() const override { return "StubStatic"; }
    std::string version() const override { return "1.0.0"; }

protected:
    const AuditCore::AuditStrategyArtifactFactory& artifactFactory() const override
    {
        static StubArtifactFactory factory;
        return factory;
    }
};

/// Build a JSON RawInput from a Json::Value.
AuditMsg::RawInput jsonInput(const ::Json::Value& value)
{
    return AuditMsg::RawInput(std::make_shared<std::string>(::Json::FastWriter().write(value)));
}

/// Key-generation input with a deterministic seed.
AuditMsg::RawInput keygenInput()
{
    ::Json::Value v;
    v["seed"] = static_cast<::Json::UInt64>(42);
    return jsonInput(v);
}

/// Maintenance input: Update on block 1 of `fileId`.
AuditMsg::RawInput maintainInput(const std::string& fileId)
{
    ::Json::Value v;
    v["fileId"] = fileId;
    v["opType"] = static_cast<::Json::UInt>(
        static_cast<std::uint8_t>(AuditMsg::MaintenanceOpType::Update));
    v["blockIndices"] = ::Json::Value(::Json::arrayValue);
    v["blockIndices"].append(static_cast<::Json::UInt64>(1));
    return jsonInput(v);
}

/// Challenge-generation input for `fileId` (deterministic, fixed block count).
AuditMsg::RawInput challengeInput(const std::string& fileId, std::size_t blockCount)
{
    ::Json::Value v;
    v["fileId"] = fileId;
    v["blockCount"] = static_cast<::Json::UInt64>(blockCount);
    v["challengeCount"] = static_cast<::Json::UInt64>(2);
    v["usePseudoRandom"] = true;
    v["seed"] = static_cast<::Json::UInt64>(7);
    return jsonInput(v);
}

/// Tag-generation input for `fileId` over `blocks`.
AuditMsg::RawInput tagsInput(const std::string& fileId,
                             const std::vector<std::vector<std::uint8_t>>& blocks)
{
    auto blockSource = std::make_shared<AuditData::MemoryAuditBlockSource>(
        blocks, blocks.empty() ? 0 : blocks.front().size(), 0);
    auto tagsMap = std::make_shared<AuditMsg::AuditDataMap>();
    tagsMap->emplace("blocks", AuditData::AuditBlockSourcePtr(blockSource));
    tagsMap->emplace("fileId", std::string(fileId));
    return AuditMsg::RawInput(tagsMap);
}

} // namespace

// ═══════════════════════════════════════════════════════════════
// Strategy travels per operation
// ═══════════════════════════════════════════════════════════════

/// Every engine operation requires context.strategy — a context without one is
/// rejected before any stage work happens.
TEST(EngineOperationStateTest, EveryOperationRequiresContextStrategy)
{
    auto engine = AuditEngineFactory::createInstance();
    AuditOperationContext ctx; // strategy deliberately left null

    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->initializeAlgorithm(AuditMsg::RawInput(), ctx); }, "strategy is null."));
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->generateKeys(AuditMsg::RawInput(), ctx); }, "strategy is null."));
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->generateTags(AuditMsg::RawInput(), ctx); }, "strategy is null."));
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->maintain(AuditMsg::RawInput(), ctx); }, "strategy is null."));
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->generateChallenges(AuditMsg::RawInput(), ctx); }, "strategy is null."));
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->generateProofs(AuditMsg::RawInput(), ctx); }, "strategy is null."));
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->verifyProofs(AuditMsg::RawInput(), ctx); }, "strategy is null."));
}

/// A successful call does not leave its strategy on the engine: the next call
/// with a fresh, unbound context fails the same way as the first one.
TEST(EngineOperationStateTest, EngineKeepsNoStrategyBetweenCalls)
{
    auto engine = AuditEngineFactory::createInstance();

    AuditOperationContext bound;
    bound.strategy = std::make_shared<DHTDynamicAuditStrategy>();
    engine->initializeAlgorithm(AuditMsg::RawInput(), bound);
    ASSERT_TRUE(bound.initializeAlgorithmResult.has_value());
    EXPECT_TRUE(bound.initializeAlgorithmResult->ok);

    AuditOperationContext unbound;
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->initializeAlgorithm(AuditMsg::RawInput(), unbound); }, "strategy is null."));
}

/// One engine, one store, one key set — only context.strategy differs, yet the
/// call outcome follows the per-context strategy.
TEST(EngineOperationStateTest, EachCallExecutesWithItsOwnContextStrategy)
{
    const std::string fileId = "engine-per-op-strategy";
    auto engine = AuditEngineFactory::createInstance();
    auto store = std::make_shared<DHTD::DynamicHashTableStateStore>();
    store->addFile(fileId, 2);

    auto healthyStrategy = std::make_shared<DHTDynamicAuditStrategy>();

    AuditOperationContext healthyCtx;
    healthyCtx.strategy = healthyStrategy;
    healthyCtx.stateStore = store;
    engine->initializeAlgorithm(AuditMsg::RawInput(), healthyCtx);
    engine->generateKeys(keygenInput(), healthyCtx);
    engine->generateChallenges(challengeInput(fileId, 2), healthyCtx);

    ASSERT_TRUE(healthyCtx.generateChallengesResult.has_value());
    auto healthyChallenges = std::dynamic_pointer_cast<DHTD::DHTDynamicChallenges>(
        healthyCtx.generateChallengesResult->challenges);
    ASSERT_NE(healthyChallenges, nullptr);
    EXPECT_GT(healthyChallenges->challengeCount(), 0u);

    // Same engine / store / keys, but this context carries a strategy that lost
    // its crypto algorithm: challenge generation must now fail.
    auto brokenStrategy = std::make_shared<DHTDynamicAuditStrategy>();
    brokenStrategy->setAlgorithm(nullptr);

    AuditOperationContext brokenCtx = healthyCtx;
    brokenCtx.strategy = brokenStrategy;
    brokenCtx.generateChallengesResult.reset();
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->generateChallenges(challengeInput(fileId, 2), brokenCtx); },
        "SM9BLS algorithm required"));
}

/// maintain() rejects a context whose strategy is not dynamic.
TEST(EngineOperationStateTest, MaintenanceRejectsNonDynamicContextStrategy)
{
    auto engine = AuditEngineFactory::createInstance();
    AuditOperationContext ctx;
    ctx.strategy = std::make_shared<StubStaticStrategy>();

    EXPECT_THROW(engine->maintain(AuditMsg::RawInput(), ctx), std::logic_error);
}

// ═══════════════════════════════════════════════════════════════
// StateStore travels per operation
// ═══════════════════════════════════════════════════════════════

/// Maintenance writes into the store of its own context: the same call against
/// a different store is rejected and leaves that store untouched.
TEST(EngineOperationStateTest, EachCallUsesItsOwnContextStateStore)
{
    const std::string fileId = "engine-per-op-store";
    auto engine = AuditEngineFactory::createInstance();
    auto strategy = std::make_shared<DHTDynamicAuditStrategy>();

    auto storeWithFile = std::make_shared<DHTD::DynamicHashTableStateStore>();
    storeWithFile->addFile(fileId, 2);

    AuditOperationContext bound;
    bound.strategy = strategy;
    bound.stateStore = storeWithFile;
    engine->maintain(maintainInput(fileId), bound);

    ASSERT_TRUE(bound.maintainResult.has_value());
    auto bumped = std::dynamic_pointer_cast<DHTD::VersionedBlockMetadata>(
        storeWithFile->getBlockMetadata(fileId, 1));
    ASSERT_NE(bumped, nullptr);
    EXPECT_EQ(bumped->version, 2u); // version=1 bumped once by this context's store

    auto emptyStore = std::make_shared<DHTD::DynamicHashTableStateStore>();
    AuditOperationContext unbound;
    unbound.strategy = strategy;
    unbound.stateStore = emptyStore;
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->maintain(maintainInput(fileId), unbound); }, "not found"));
    EXPECT_FALSE(unbound.maintainResult.has_value());
    EXPECT_FALSE(emptyStore->hasFile(fileId));
}

/// Tag generation registers the file in the store of its own context, and is
/// rejected when that context carries no store.
TEST(EngineOperationStateTest, TagGenerationUsesTheContextStateStore)
{
    const std::string fileId = "engine-tags-store";
    auto engine = AuditEngineFactory::createInstance();
    auto strategy = std::make_shared<DHTDynamicAuditStrategy>();
    auto store = std::make_shared<DHTD::DynamicHashTableStateStore>();

    AuditOperationContext ctx;
    ctx.strategy = strategy;
    ctx.stateStore = store;
    engine->initializeAlgorithm(AuditMsg::RawInput(), ctx);
    engine->generateKeys(keygenInput(), ctx);

    const std::vector<std::vector<std::uint8_t>> blocks(
        2, std::vector<std::uint8_t>(32, 0xAB));

    engine->generateTags(tagsInput(fileId, blocks), ctx);
    ASSERT_TRUE(ctx.generateTagsResult.has_value());
    ASSERT_NE(ctx.generateTagsResult->tags, nullptr);
    EXPECT_TRUE(store->hasFile(fileId));
    EXPECT_EQ(store->getBlockCount(fileId), 2u);

    // The same call without a store on the context is rejected.
    AuditOperationContext noStore = ctx;
    noStore.stateStore.reset();
    noStore.generateTagsResult.reset();
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->generateTags(tagsInput(fileId, blocks), noStore); }, "stateStore"));
}

/// DHTDynamic degradation contract: challenge generation without a usable store
/// stays non-fatal — no store means no challenge set, an unknown file means an
/// empty challenge set.
TEST(EngineOperationStateTest, ChallengeGenerationDegradesWithoutUsableStateStore)
{
    const std::string fileId = "engine-challenge-degrade";
    auto engine = AuditEngineFactory::createInstance();
    auto strategy = std::make_shared<DHTDynamicAuditStrategy>();
    auto store = std::make_shared<DHTD::DynamicHashTableStateStore>();
    store->addFile(fileId, 2);

    AuditOperationContext ctx;
    ctx.strategy = strategy;
    ctx.stateStore = store;
    engine->initializeAlgorithm(AuditMsg::RawInput(), ctx);
    engine->generateKeys(keygenInput(), ctx);

    // (a) No store bound to this operation → no challenges, no exception.
    AuditOperationContext noStore = ctx;
    noStore.stateStore.reset();
    engine->generateChallenges(challengeInput(fileId, 2), noStore);
    ASSERT_TRUE(noStore.generateChallengesResult.has_value());
    EXPECT_EQ(noStore.generateChallengesResult->challenges, nullptr);

    // (b) Store bound but file unknown → empty challenge set.
    AuditOperationContext unknownFile = ctx;
    unknownFile.stateStore = std::make_shared<DHTD::DynamicHashTableStateStore>();
    engine->generateChallenges(challengeInput(fileId, 2), unknownFile);
    ASSERT_TRUE(unknownFile.generateChallengesResult.has_value());
    auto emptyChallenges = std::dynamic_pointer_cast<DHTD::DHTDynamicChallenges>(
        unknownFile.generateChallengesResult->challenges);
    ASSERT_NE(emptyChallenges, nullptr);
    EXPECT_EQ(emptyChallenges->challengeCount(), 0u);
}

// ═══════════════════════════════════════════════════════════════
// createStateStore takes an explicit strategy
// ═══════════════════════════════════════════════════════════════

/// Each call builds a fresh store of the strategy's own type.
TEST(EngineStateStoreCreationTest, BuildsFreshStorePerCall)
{
    auto engine = AuditEngineFactory::createInstance();
    auto strategy = std::make_shared<DHTDynamicAuditStrategy>();

    auto store1 = engine->createStateStore(strategy);
    auto store2 = engine->createStateStore(strategy);

    ASSERT_NE(store1, nullptr);
    ASSERT_NE(store2, nullptr);
    EXPECT_NE(store1.get(), store2.get());
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DynamicHashTableStateStore>(store1), nullptr);
    EXPECT_TRUE(store1->listFiles().empty());
}

/// Null and non-dynamic strategies are rejected before any store is built.
TEST(EngineStateStoreCreationTest, RejectsNullAndNonDynamicStrategies)
{
    auto engine = AuditEngineFactory::createInstance();

    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->createStateStore(nullptr); }, "no strategy configured"));
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->createStateStore(std::make_shared<StubStaticStrategy>()); },
        "not dynamic"));
}

/// Engine helpers take the strategy explicitly instead of holding one.
TEST(EngineStrategySelectionTest, ArtifactAndAlgorithmTypeUseTheGivenStrategy)
{
    auto engine = AuditEngineFactory::createInstance();
    auto strategy = std::make_shared<DHTDynamicAuditStrategy>();

    EXPECT_EQ(engine->algorithmType(strategy), "DHTDynamic");

    auto artifact = engine->createArtifact(strategy, AuditCore::AuditArtifactKind::Challenges);
    auto challenges = std::get_if<AuditMsg::ChallengesPtr>(&artifact);
    ASSERT_NE(challenges, nullptr);
    ASSERT_NE(*challenges, nullptr);
    EXPECT_NE(std::dynamic_pointer_cast<DHTD::DHTDynamicChallenges>(*challenges), nullptr);

    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->createArtifact(nullptr, AuditCore::AuditArtifactKind::Challenges); },
        "strategy is null."));
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { engine->algorithmType(nullptr); }, "strategy is null."));
}
