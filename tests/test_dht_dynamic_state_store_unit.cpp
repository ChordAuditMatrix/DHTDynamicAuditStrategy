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
 * @file test_dht_dynamic_state_store_unit.cpp
 * @brief Unit tests for DHTDynamic strategy ↔ StateStore interaction using Mock.
 * @details Uses a hand-rolled MockDynamicPdpStateStore (defined inline) to
 *          verify that the DHTDynamicAuditStrategy calls the correct StateStore
 *          methods with correct arguments during each pipeline stage.
 *
 *          The mock records all method invocations (method name + arguments)
 *          so tests can assert on call ordering, argument correctness, and
 *          call counts — without depending on DynamicHashTableStateStore
 *          or any real storage backend.
 *
 * Test Intent Summary:
 * - Verify generateChallenges calls getBlockCount + getBlockMetadata per block.
 * - Verify maintenance Update calls getBlockMetadata then modifyBlock with
 *   version+1 and updated timestamp.
 * - Verify maintenance Insert calls insertBlock with version=1 metadata.
 * - Verify maintenance Delete calls deleteBlock.
 * - Verify strategy rejects operations when stateStore is not injected.
 * - Verify strategy rejects maintenance when file does not exist in stateStore.
 * - Verify getBlockMetadata arguments use 1-based blockIndex convention.
 *
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-07-09
 */

// ── Strategy & types ──
#include "DHTDynamicAuditStrategy/strategy.h"
#include "DHTDynamicAuditStrategy/common.h"
#include "DHTDynamicAuditStrategy/params.h"
#include "DHTDynamicAuditStrategy/challenges.h"
#include "DHTDynamicAuditStrategy/tags.h"
#include "DHTDynamicAuditStrategy/state_stores/versioned_block_metadata.h"
#include "DHTDynamicAuditStrategy/maintain_types.h"
#include "DHTDynamicAuditStrategy/request_ext.h"
#include "DHTDynamicAuditStrategy/state_stores/dynamic_hash_table_state_store.h"

// ── Interface types ──
#include "ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/request_result.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/challenges.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/tags.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/in_memory_tags.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/tag.h"
#include "ChordAuditMatrixLib/interfaces/audit/state_stores/block_metadata.h"
#include "ChordAuditMatrixLib/interfaces/audit/state_stores/block_metadata_collection.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

// ═══════════════════════════════════════════════════════════════
// Namespace aliases
// ═══════════════════════════════════════════════════════════════

namespace AuditCore  = CAMatrix::Audit::Core;
namespace AuditMsg   = CAMatrix::Audit::Messages;
namespace AuditStrat = CAMatrix::Audit::Strategies;
namespace DHTD       = CAMatrix::Audit::Strategies::DHTDynamic;

// ═══════════════════════════════════════════════════════════════
// MockDynamicPdpStateStore — inline mock for unit testing
// ═══════════════════════════════════════════════════════════════

namespace {

/// Records a single method invocation on the mock.
struct MethodCall {
    std::string method;
    std::string fileId;
    std::size_t blockIndex = 0;
    std::uint64_t metaVersion = 0;
    std::uint64_t metaTimestamp = 0;
};

/// Hand-rolled mock for DynamicPdpStateStore. Records all method calls for
/// verification and backs queries with a simple in-memory store.
class MockDynamicPdpStateStore final : public AuditCore::DynamicPdpStateStore {
public:
    std::vector<MethodCall> calls;

    void reset() { calls.clear(); }

    [[nodiscard]] std::size_t countCalls(const std::string &methodName) const
    {
        std::size_t n = 0;
        for (const auto &c : calls) if (c.method == methodName) ++n;
        return n;
    }

    [[nodiscard]] const MethodCall *findCall(const std::string &methodName, std::size_t nth = 0) const
    {
        std::size_t seen = 0;
        for (const auto &c : calls) {
            if (c.method == methodName) {
                if (seen == nth) return &c;
                ++seen;
            }
        }
        return nullptr;
    }

    void addFile(const std::string &fileId) override
    {
        calls.push_back({"addFile", fileId, 0, 0, 0});
        files_[fileId] = FileEntry{};
    }

    void addFile(const std::string &fileId, std::size_t blockCount) override
    {
        calls.push_back({"addFile", fileId, blockCount, 0, 0});
        FileEntry entry;
        for (std::size_t i = 1; i <= blockCount; ++i) {
            entry.blocks[i] = std::make_shared<DHTD::VersionedBlockMetadata>();
        }
        files_[fileId] = std::move(entry);
    }

    void removeFile(const std::string &fileId) override
    {
        calls.push_back({"removeFile", fileId, 0, 0, 0});
        files_.erase(fileId);
    }

    [[nodiscard]] bool hasFile(const std::string &fileId) const override
    {
        return files_.count(fileId) > 0;
    }

    [[nodiscard]] std::shared_ptr<AuditCore::BlockMetadata> getBlockMetadata(
        const std::string &fileId, std::size_t blockIndex) const override
    {
        const_cast<MockDynamicPdpStateStore *>(this)->calls.push_back(
            {"getBlockMetadata", fileId, blockIndex, 0, 0});

        auto it = files_.find(fileId);
        if (it == files_.end()) {
            throw std::runtime_error("MockStateStore: file '" + fileId + "' not found");
        }
        const auto &entry = it->second;
        auto blockIt = entry.blocks.find(blockIndex);
        if (blockIt == entry.blocks.end()) {
            throw std::runtime_error("MockStateStore: block index " +
                std::to_string(blockIndex) + " out of range for file '" + fileId + "'");
        }
        return blockIt->second;
    }

    [[nodiscard]] std::size_t getBlockCount(const std::string &fileId) const override
    {
        const_cast<MockDynamicPdpStateStore *>(this)->calls.push_back(
            {"getBlockCount", fileId, 0, 0, 0});

        auto it = files_.find(fileId);
        if (it == files_.end()) {
            throw std::runtime_error("MockStateStore: file '" + fileId + "' not found");
        }
        return it->second.blocks.size();
    }

    [[nodiscard]] AuditCore::BlockMetadataCollectionPtr getBlockMetadataCollection(
        const std::string &fileId) const override
    {
        const_cast<MockDynamicPdpStateStore *>(this)->calls.push_back(
            {"getBlockMetadataCollection", fileId, 0, 0, 0});
        return nullptr;
    }

    void modifyBlock(const std::string &fileId, std::size_t blockIndex) override
    {
        auto it = files_.find(fileId);
        if (it == files_.end()) {
            throw std::runtime_error("MockStateStore: file '" + fileId + "' not found");
        }
        auto blockIt = it->second.blocks.find(blockIndex);
        if (blockIt == it->second.blocks.end()) {
            throw std::runtime_error("MockStateStore: block index out of range");
        }
        auto dynMeta = std::dynamic_pointer_cast<DHTD::VersionedBlockMetadata>(blockIt->second);
        std::uint64_t ver = 0, ts = 0;
        if (dynMeta) {
            dynMeta->bump();
            ver = dynMeta->version;
            ts  = dynMeta->timestamp;
        }
        calls.push_back({"modifyBlock", fileId, blockIndex, ver, ts});
    }

    void insertBlock(const std::string &fileId, std::size_t blockIndex) override
    {
        const auto now = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        auto metadata = std::make_shared<DHTD::VersionedBlockMetadata>(1, now);

        calls.push_back({"insertBlock", fileId, blockIndex, metadata->version, metadata->timestamp});

        auto it = files_.find(fileId);
        if (it == files_.end()) {
            throw std::runtime_error("MockStateStore: file '" + fileId + "' not found");
        }
        if (it->second.blocks.find(blockIndex) != it->second.blocks.end()) {
            throw std::runtime_error("MockStateStore: insert index already occupied");
        }
        it->second.blocks[blockIndex] = std::move(metadata);
    }

    void deleteBlock(const std::string &fileId, std::size_t blockIndex) override
    {
        calls.push_back({"deleteBlock", fileId, blockIndex, 0, 0});

        auto it = files_.find(fileId);
        if (it == files_.end()) {
            throw std::runtime_error("MockStateStore: file '" + fileId + "' not found");
        }
        auto blockIt = it->second.blocks.find(blockIndex);
        if (blockIt == it->second.blocks.end()) {
            throw std::runtime_error("MockStateStore: block index out of range");
        }
        it->second.blocks.erase(blockIt);
    }

    [[nodiscard]] std::vector<std::string> listFiles() const override
    {
        const_cast<MockDynamicPdpStateStore *>(this)->calls.push_back({"listFiles", "", 0, 0, 0});
        std::vector<std::string> result;
        result.reserve(files_.size());
        for (const auto &kv : files_) {
            result.push_back(kv.first);
        }
        return result;
    }

    void setBlockMetadataCollection(
        const std::string &fileId, AuditCore::BlockMetadataCollectionPtr collection) override
    {
        const_cast<MockDynamicPdpStateStore *>(this)->calls.push_back(
            {"setBlockMetadataCollection", fileId, 0, 0, 0});
        // Store the collection (simple mock — just accept it)
        auto it = files_.find(fileId);
        if (it == files_.end()) {
            throw std::runtime_error("MockStateStore: file '" + fileId + "' not found");
        }
        it->second.collection = std::move(collection);
    }

public:
    /// Add a file with N blocks, each starting at (startVersion, startTimestamp).
    void addFileWithBlocks(const std::string &fileId, std::size_t blockCount,
                            std::uint64_t startVersion = 1, std::uint64_t startTimestamp = 0)
    {
        FileEntry entry;
        for (std::size_t i = 1; i <= blockCount; ++i) {
            entry.blocks[i] = std::make_shared<DHTD::VersionedBlockMetadata>(
                startVersion, startTimestamp);
        }
        files_[fileId] = std::move(entry);
    }

private:
    struct FileEntry {
        std::map<std::size_t, std::shared_ptr<AuditCore::BlockMetadata>> blocks;
        AuditCore::BlockMetadataCollectionPtr collection;
    };
    std::map<std::string, FileEntry> files_;
    std::uint64_t version_ = 1;
};

/// Create a strategy with `mock` as its stateStore.
std::shared_ptr<AuditStrat::DHTDynamicAuditStrategy>
createStrategyWithMock(const std::shared_ptr<MockDynamicPdpStateStore> &mock)
{
    auto strategy = std::make_shared<AuditStrat::DHTDynamicAuditStrategy>();
    strategy->setStateStore(mock);
    return strategy;
}

/// Generate a real DHTDynamicPublicParams via a real stateStore-backed strategy.
std::shared_ptr<DHTD::DHTDynamicPublicParams> generateRealPublicParams(std::uint64_t seed)
{
    auto realStore = std::make_shared<DHTD::DynamicHashTableStateStore>();
    auto realStrategy = std::make_shared<AuditStrat::DHTDynamicAuditStrategy>();
    realStrategy->setStateStore(realStore);

    AuditMsg::InitializeAlgorithmRequest initReq;
    initReq.ext = std::make_shared<DHTD::DHTDynamicAlgoInitRequestExt>();
    realStrategy->initializeAlgorithm(initReq);

    AuditMsg::GenerateKeysRequest keyReq;
    auto keyReqExt = std::make_shared<DHTD::DHTDynamicKeyGenRequestExt>();
    keyReqExt->seed = seed;
    keyReq.ext = keyReqExt;
    auto keyRes = realStrategy->generateKeys(keyReq);
    return std::dynamic_pointer_cast<DHTD::DHTDynamicPublicParams>(keyRes.publicParams);
}

/// Build a MaintainRequest with the given op + block indices.
AuditMsg::MaintainRequest buildMaintainRequest(
    const std::string &fileId, AuditMsg::MaintenanceOpType op,
    const std::vector<std::size_t> &blockIndices)
{
    AuditMsg::MaintainRequest req;
    auto ext = std::make_shared<DHTD::DHTDynamicMaintainExt>();
    ext->fileId = fileId;
    ext->opType = op;
    ext->blockIndices = blockIndices;
    req.ext = ext;
    if (op != AuditMsg::MaintenanceOpType::Delete) {
        req.tags = std::make_shared<AuditMsg::InMemoryTags>(
            [] { return std::make_shared<DHTD::DHTDynamicTag>(); });
    }
    return req;
}

/// Assert that `expr` throws std::runtime_error whose message contains `needle`.
::testing::AssertionResult throwsRuntimeErrorContaining(const std::function<void()> &expr,
                                                       const std::string &needle)
{
    try {
        expr();
        return ::testing::AssertionFailure()
            << "expected std::runtime_error containing \"" << needle << "\", but no exception was thrown";
    } catch (const std::runtime_error &e) {
        if (std::string(e.what()).find(needle) == std::string::npos) {
            return ::testing::AssertionFailure()
                << "exception message does not contain \"" << needle << "\": " << e.what();
        }
        return ::testing::AssertionSuccess();
    } catch (const std::exception &e) {
        return ::testing::AssertionFailure()
            << "expected std::runtime_error, got " << typeid(e).name() << ": " << e.what();
    }
}

} // namespace

// ============================================================================
// generateChallenges → stateStore interaction
// ============================================================================

/// generateChallenges with ext->blockCount set must NOT call getBlockCount
/// (blockCount takes priority) and must call getBlockMetadata once per
/// challenge item, using 1-based block indices.
TEST(DhtDynamicGenerateChallenges, QueriesBlockMetadataPerChallengeItem)
{
    auto mock = std::make_shared<MockDynamicPdpStateStore>();
    mock->addFileWithBlocks("f1", 3);
    auto strategy = createStrategyWithMock(mock);

    AuditMsg::GenerateChallengesRequest req;
    auto ext = std::make_shared<DHTD::DHTDynamicChallengeRequestExt>();
    ext->fileId = "f1";
    ext->blockCount = 3;
    ext->challengeCount = 2;
    ext->usePseudoRandom = true;
    ext->seed = 42;
    ext->userPublicParams = generateRealPublicParams(12345);
    ASSERT_NE(ext->userPublicParams, nullptr);
    req.ext = ext;

    mock->reset();
    auto result = strategy->generateChallenges(req);

    // ext->blockCount takes priority over getBlockCount.
    EXPECT_EQ(mock->countCalls("getBlockCount"), 0u);

    // One getBlockMetadata call per challenge item.
    const std::size_t metadataCalls = mock->countCalls("getBlockMetadata");
    EXPECT_EQ(metadataCalls, 2u);
    for (std::size_t i = 0; i < metadataCalls; ++i) {
        const auto *call = mock->findCall("getBlockMetadata", i);
        ASSERT_NE(call, nullptr);
        EXPECT_EQ(call->fileId, "f1");
        EXPECT_GE(call->blockIndex, 1u);
        EXPECT_LE(call->blockIndex, 3u);
    }

    ASSERT_NE(result.challenges, nullptr);
    auto dynChal = std::dynamic_pointer_cast<DHTD::DHTDynamicChallenges>(result.challenges);
    ASSERT_NE(dynChal, nullptr);
    EXPECT_EQ(dynChal->challengeCount(), 2u);
}

/// generateChallenges with ext->blockCount == 0 must fall back to
/// stateStore->getBlockCount() and resolve the real block count.
TEST(DhtDynamicGenerateChallenges, FallsBackToGetBlockCountWhenBlockCountIsZero)
{
    auto mock = std::make_shared<MockDynamicPdpStateStore>();
    mock->addFileWithBlocks("f1", 5);
    auto strategy = createStrategyWithMock(mock);

    AuditMsg::GenerateChallengesRequest req;
    auto ext = std::make_shared<DHTD::DHTDynamicChallengeRequestExt>();
    ext->fileId = "f1";
    ext->blockCount = 0; // triggers fallback
    ext->challengeCount = 2;
    ext->usePseudoRandom = true;
    ext->seed = 42;
    ext->userPublicParams = generateRealPublicParams(99999);
    ASSERT_NE(ext->userPublicParams, nullptr);
    req.ext = ext;

    mock->reset();
    auto result = strategy->generateChallenges(req);

    EXPECT_GE(mock->countCalls("getBlockCount"), 1u);
    ASSERT_NE(result.challenges, nullptr);
    auto dynChal = std::dynamic_pointer_cast<DHTD::DHTDynamicChallenges>(result.challenges);
    ASSERT_NE(dynChal, nullptr);
    EXPECT_EQ(dynChal->blockCount(), 5u);
}

// ============================================================================
// maintenance Update
// ============================================================================

/// Update on a single block: reads metadata via getBlockMetadata, then
/// modifyBlock bumps version (3→4) and refreshes timestamp (>100).
TEST(DhtDynamicMaintenanceUpdate, ReadsThenModifiesBlockWithBumpedVersion)
{
    auto mock = std::make_shared<MockDynamicPdpStateStore>();
    mock->addFileWithBlocks("f1", 2, /*startVersion=*/3, /*startTimestamp=*/100);
    auto strategy = createStrategyWithMock(mock);

    mock->reset();
    strategy->maintenance(buildMaintainRequest("f1", AuditMsg::MaintenanceOpType::Update, {2}));

    EXPECT_EQ(mock->countCalls("getBlockMetadata"), 1u);
    const auto *getCall = mock->findCall("getBlockMetadata", 0);
    ASSERT_NE(getCall, nullptr);
    EXPECT_EQ(getCall->fileId, "f1");
    EXPECT_EQ(getCall->blockIndex, 2u);

    EXPECT_EQ(mock->countCalls("modifyBlock"), 1u);
    const auto *modCall = mock->findCall("modifyBlock", 0);
    ASSERT_NE(modCall, nullptr);
    EXPECT_EQ(modCall->fileId, "f1");
    EXPECT_EQ(modCall->blockIndex, 2u);
    EXPECT_EQ(modCall->metaVersion, 4u); // bumped from 3
    EXPECT_GT(modCall->metaTimestamp, 100u);
}

/// Update on multiple blocks: each block gets getBlockMetadata + modifyBlock
/// in order, version bumped from 1 → 2.
TEST(DhtDynamicMaintenanceUpdate, HandlesMultipleBlocksInOrder)
{
    auto mock = std::make_shared<MockDynamicPdpStateStore>();
    mock->addFileWithBlocks("f1", 4);
    auto strategy = createStrategyWithMock(mock);

    mock->reset();
    strategy->maintenance(buildMaintainRequest("f1", AuditMsg::MaintenanceOpType::Update, {1, 3}));

    EXPECT_EQ(mock->countCalls("getBlockMetadata"), 2u);
    EXPECT_EQ(mock->countCalls("modifyBlock"), 2u);

    const auto *mod0 = mock->findCall("modifyBlock", 0);
    ASSERT_NE(mod0, nullptr);
    EXPECT_EQ(mod0->blockIndex, 1u);
    EXPECT_EQ(mod0->metaVersion, 2u); // bumped from 1

    const auto *mod1 = mock->findCall("modifyBlock", 1);
    ASSERT_NE(mod1, nullptr);
    EXPECT_EQ(mod1->blockIndex, 3u);
    EXPECT_EQ(mod1->metaVersion, 2u);
}

/// Update on a block with version=5 bumps to 6, timestamp refreshed (>500).
TEST(DhtDynamicMaintenanceUpdate, BumpsVersionFromFiveToSix)
{
    auto mock = std::make_shared<MockDynamicPdpStateStore>();
    mock->addFileWithBlocks("f1", 1, /*startVersion=*/5, /*startTimestamp=*/500);
    auto strategy = createStrategyWithMock(mock);

    mock->reset();
    strategy->maintenance(buildMaintainRequest("f1", AuditMsg::MaintenanceOpType::Update, {1}));

    const auto *call = mock->findCall("modifyBlock", 0);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->metaVersion, 6u); // bumped from 5
    EXPECT_GT(call->metaTimestamp, 500u);
}

// ============================================================================
// maintenance Insert
// ============================================================================

/// Insert at a new blockIndex: insertBlock called once with version=1,
/// timestamp=now, correct fileId/blockIndex.
TEST(DhtDynamicMaintenanceInsert, CallsInsertBlockWithVersionOne)
{
    auto mock = std::make_shared<MockDynamicPdpStateStore>();
    mock->addFileWithBlocks("f1", 2);
    auto strategy = createStrategyWithMock(mock);

    mock->reset();
    strategy->maintenance(buildMaintainRequest("f1", AuditMsg::MaintenanceOpType::Insert, {3}));

    EXPECT_EQ(mock->countCalls("insertBlock"), 1u);
    const auto *call = mock->findCall("insertBlock", 0);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->fileId, "f1");
    EXPECT_EQ(call->blockIndex, 3u);
    EXPECT_EQ(call->metaVersion, 1u);
    EXPECT_GT(call->metaTimestamp, 0u);
}

// ============================================================================
// maintenance Delete
// ============================================================================

/// Delete on a single block: deleteBlock called once; must NOT call
/// getBlockMetadata or modifyBlock.
TEST(DhtDynamicMaintenanceDelete, CallsDeleteBlockOnly)
{
    auto mock = std::make_shared<MockDynamicPdpStateStore>();
    mock->addFileWithBlocks("f1", 3);
    auto strategy = createStrategyWithMock(mock);

    mock->reset();
    strategy->maintenance(buildMaintainRequest("f1", AuditMsg::MaintenanceOpType::Delete, {2}));

    EXPECT_EQ(mock->countCalls("deleteBlock"), 1u);
    const auto *call = mock->findCall("deleteBlock", 0);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->fileId, "f1");
    EXPECT_EQ(call->blockIndex, 2u);

    // Delete must not read or modify block metadata.
    EXPECT_EQ(mock->countCalls("getBlockMetadata"), 0u);
    EXPECT_EQ(mock->countCalls("modifyBlock"), 0u);
}

/// Delete on multiple blocks: deleteBlock called once per block, in order,
/// with 1-based indices {1, 3, 5}.
TEST(DhtDynamicMaintenanceDelete, HandlesMultipleBlocksInOrder)
{
    auto mock = std::make_shared<MockDynamicPdpStateStore>();
    mock->addFileWithBlocks("f1", 5);
    auto strategy = createStrategyWithMock(mock);

    mock->reset();
    strategy->maintenance(buildMaintainRequest("f1", AuditMsg::MaintenanceOpType::Delete, {1, 3, 5}));

    EXPECT_EQ(mock->countCalls("deleteBlock"), 3u);
    const std::size_t expected[3] = {1, 3, 5};
    for (std::size_t i = 0; i < 3; ++i) {
        const auto *call = mock->findCall("deleteBlock", i);
        ASSERT_NE(call, nullptr) << "missing deleteBlock call " << i;
        EXPECT_EQ(call->blockIndex, expected[i]);
    }
}

// ============================================================================
// Error paths
// ============================================================================

/// maintenance without stateStore injected must throw std::runtime_error
/// whose message mentions "stateStore".
TEST(DhtDynamicMaintenanceErrors, ThrowsWithoutStateStore)
{
    auto strategy = std::make_shared<AuditStrat::DHTDynamicAuditStrategy>();
    // Deliberately not calling setStateStore.
    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { strategy->maintenance(buildMaintainRequest("f1", AuditMsg::MaintenanceOpType::Update, {1})); },
        "stateStore"));
}

/// maintenance on a fileId not present in the stateStore must throw
/// std::runtime_error whose message mentions "not found".
TEST(DhtDynamicMaintenanceErrors, ThrowsWhenFileNotInStateStore)
{
    auto mock = std::make_shared<MockDynamicPdpStateStore>(); // no files
    auto strategy = createStrategyWithMock(mock);

    EXPECT_TRUE(throwsRuntimeErrorContaining(
        [&] { strategy->maintenance(buildMaintainRequest("nonexistent", AuditMsg::MaintenanceOpType::Update, {1})); },
        "not found"));
}
