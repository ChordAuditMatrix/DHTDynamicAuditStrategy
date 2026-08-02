/*
 * Copyright (C) 2021-2026, Dylan Liu
 *
 * DynamicHashTableStateStore Unit Tests
 * Verifies the real (non-mock) DynamicHashTableStateStore implementation:
 * file lifecycle, block queries, maintenance operations with index shifting,
 * and serialization roundtrips.
 *
 * The existing test_dht_dynamic_state_store_unit.cpp uses a hand-rolled mock
 * to verify the strategy ↔ store *interface contract*. This file exercises the
 * the insert/delete shift algorithms, and index conversion.
 */

#include "DHTDynamicAuditStrategy/state_stores/dynamic_hash_table_state_store.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/in_memory_block_metadata_collection.h"
#include "DHTDynamicAuditStrategy/state_stores/versioned_block_metadata.h"
#include "ChordAuditMatrixLib/interfaces/audit/state_stores/block_metadata.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace CAMatrix::Audit::Core;
using namespace CAMatrix::Audit::Strategies::DHTDynamic;

// Test Intent Summary:
// - File lifecycle: addFile (empty + with blockCount), removeFile, hasFile,
//   duplicate-add and missing-file error paths.
// - Block queries: getBlockMetadata (1-based indexing), getBlockCount,
//   getBlockMetadataCollection; out-of-range and missing-file errors.
// - Maintenance: modifyBlock (bumps version+timestamp), insertBlock (shifts
//   indices up), deleteBlock (shifts indices down); error paths.
// - Persistence: saveEntry/restoreEntry roundtrip, saveAll, createEmpty,
//   restoreEntry-into-existing-file error path.

// ============================================================================
// Helpers
// ============================================================================
namespace {

/// Stable timestamp so assertions on VersionedBlockMetadata are deterministic.
constexpr std::uint64_t kFixedTs = 1'700'000'000;

/// Factory that builds a VersionedBlockMetadata with a fixed timestamp so tests
/// can assert on version/timestamp values without flakiness.
InMemoryBlockMetadataCollection::BlockMetadataFactory fixedTimestampFactory()
{
    return []() -> std::shared_ptr<BlockMetadata> {
        return std::make_shared<VersionedBlockMetadata>(1, kFixedTs);
    };
}

/// Downcast a BlockMetadata to VersionedBlockMetadata (or fail the test).
std::shared_ptr<VersionedBlockMetadata>
asVersioned(const std::shared_ptr<BlockMetadata> &meta)
{
    auto v = std::dynamic_pointer_cast<VersionedBlockMetadata>(meta);
    EXPECT_NE(v, nullptr);
    return v;
}

} // namespace

// ============================================================================
// Fixture: a fresh DynamicHashTableStateStore with fixed-timestamp factory
// ============================================================================
class DynamicHashTableStateStoreTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        store_ = std::make_shared<DynamicHashTableStateStore>(fixedTimestampFactory());
    }

    /// Add a file with `blockCount` pre-initialized blocks, all version=1.
    void addFileWithBlocks(const std::string &fileId, std::size_t blockCount)
    {
        store_->addFile(fileId, blockCount);
    }

    std::shared_ptr<DynamicHashTableStateStore> store_;
};

// ============================================================================
// File lifecycle
// ============================================================================
TEST_F(DynamicHashTableStateStoreTest, AddEmptyFileCreatesZeroBlockFile)
{
    store_->addFile("f1");
    EXPECT_TRUE(store_->hasFile("f1"));
    EXPECT_EQ(store_->getBlockCount("f1"), 0u);
}

TEST_F(DynamicHashTableStateStoreTest, AddFileWithBlockCountInitializesBlocks)
{
    store_->addFile("f1", 3);
    EXPECT_EQ(store_->getBlockCount("f1"), 3u);
    for (std::size_t i = 1; i <= 3; ++i) {
        auto meta = store_->getBlockMetadata("f1", i);
        auto v = asVersioned(meta);
        ASSERT_NE(v, nullptr);
        EXPECT_EQ(v->version, 1u);
        EXPECT_EQ(v->timestamp, kFixedTs);
    }
}

TEST_F(DynamicHashTableStateStoreTest, AddFileRejectsDuplicate)
{
    store_->addFile("f1");
    EXPECT_THROW(store_->addFile("f1"), std::runtime_error);
}

TEST_F(DynamicHashTableStateStoreTest, AddFileWithBlockCountRejectsZero)
{
    EXPECT_THROW(store_->addFile("f1", 0), std::invalid_argument);
}

TEST_F(DynamicHashTableStateStoreTest, RemoveFileDeletesIt)
{
    store_->addFile("f1", 2);
    store_->removeFile("f1");
    EXPECT_FALSE(store_->hasFile("f1"));
}

TEST_F(DynamicHashTableStateStoreTest, RemoveFileRejectsMissingFile)
{
    EXPECT_THROW(store_->removeFile("nope"), std::runtime_error);
}

TEST_F(DynamicHashTableStateStoreTest, HasFileReturnsFalseForUnknownId)
{
    EXPECT_FALSE(store_->hasFile("unknown"));
}

// ============================================================================
// Block queries: 1-based indexing
// ============================================================================
TEST_F(DynamicHashTableStateStoreTest, GetBlockMetadataUsesOneBasedIndexing)
{
    store_->addFile("f1", 3);
    // blockIndex 1 is the first block (collection index 0)
    auto meta1 = store_->getBlockMetadata("f1", 1);
    auto meta2 = store_->getBlockMetadata("f1", 2);
    ASSERT_NE(meta1, nullptr);
    ASSERT_NE(meta2, nullptr);
    // Each block is an independent metadata instance
    EXPECT_NE(meta1.get(), meta2.get());
}

TEST_F(DynamicHashTableStateStoreTest, GetBlockMetadataRejectsZeroIndex)
{
    store_->addFile("f1", 2);
    // blockIndex 0 is invalid (1-based) — collIdx = -1 underflows; behavior
    // is a runtime_error from contains() on a huge index.
    EXPECT_THROW(store_->getBlockMetadata("f1", 0), std::runtime_error);
}

TEST_F(DynamicHashTableStateStoreTest, GetBlockMetadataRejectsOutOfRangeIndex)
{
    store_->addFile("f1", 2);
    EXPECT_THROW(store_->getBlockMetadata("f1", 3), std::runtime_error);
}

TEST_F(DynamicHashTableStateStoreTest, GetBlockMetadataRejectsMissingFile)
{
    EXPECT_THROW(store_->getBlockMetadata("nope", 1), std::runtime_error);
}

TEST_F(DynamicHashTableStateStoreTest, GetBlockCountRejectsMissingFile)
{
    EXPECT_THROW(store_->getBlockCount("nope"), std::runtime_error);
}

TEST_F(DynamicHashTableStateStoreTest, GetBlockMetadataCollectionReturnsPopulatedCollection)
{
    store_->addFile("f1", 2);
    auto coll = store_->getBlockMetadataCollection("f1");
    ASSERT_NE(coll, nullptr);
    EXPECT_EQ(coll->size(), 2u);
    EXPECT_FALSE(coll->empty());
    EXPECT_EQ(coll->maxIndex(), 2u);
}

TEST_F(DynamicHashTableStateStoreTest, GetBlockMetadataCollectionRejectsMissingFile)
{
    EXPECT_THROW(store_->getBlockMetadataCollection("nope"), std::runtime_error);
}

// ============================================================================
// Maintenance: modifyBlock
// ============================================================================
TEST_F(DynamicHashTableStateStoreTest, ModifyBlockBumpsVersionAndTimestamp)
{
    store_->addFile("f1", 1);
    auto before = asVersioned(store_->getBlockMetadata("f1", 1));
    ASSERT_NE(before, nullptr);
    EXPECT_EQ(before->version, 1u);

    store_->modifyBlock("f1", 1);

    auto after = asVersioned(store_->getBlockMetadata("f1", 1));
    ASSERT_NE(after, nullptr);
    EXPECT_EQ(after->version, 2u);
    // Timestamp refreshed to "now" — must be >= fixed baseline.
    EXPECT_GE(after->timestamp, kFixedTs);
}

TEST_F(DynamicHashTableStateStoreTest, ModifyBlockRejectsOutOfRangeIndex)
{
    store_->addFile("f1", 1);
    EXPECT_THROW(store_->modifyBlock("f1", 2), std::runtime_error);
}

TEST_F(DynamicHashTableStateStoreTest, ModifyBlockRejectsMissingFile)
{
    EXPECT_THROW(store_->modifyBlock("nope", 1), std::runtime_error);
}

// ============================================================================
// Maintenance: insertBlock (shifts existing entries at index+ upward)
// ============================================================================
TEST_F(DynamicHashTableStateStoreTest, InsertBlockAtEndAppendsNewBlock)
{
    store_->addFile("f1", 2);
    store_->insertBlock("f1", 3); // append at the end
    EXPECT_EQ(store_->getBlockCount("f1"), 3u);
    auto newMeta = asVersioned(store_->getBlockMetadata("f1", 3));
    ASSERT_NE(newMeta, nullptr);
    EXPECT_EQ(newMeta->version, 1u); // fresh metadata
}

TEST_F(DynamicHashTableStateStoreTest, InsertBlockInMiddleShiftsAboveUp)
{
    store_->addFile("f1", 3);
    // Before: blocks 1,2,3 (versions 1,1,1)
    store_->insertBlock("f1", 2); // insert at position 2
    // After: blocks 1..4; old block 2 is now block 3, old block 3 is now block 4
    EXPECT_EQ(store_->getBlockCount("f1"), 4u);

    auto b1 = asVersioned(store_->getBlockMetadata("f1", 1));
    auto b2 = asVersioned(store_->getBlockMetadata("f1", 2)); // new block
    auto b3 = asVersioned(store_->getBlockMetadata("f1", 3)); // was b2
    auto b4 = asVersioned(store_->getBlockMetadata("f1", 4)); // was b3
    ASSERT_NE(b1, nullptr);
    ASSERT_NE(b2, nullptr);
    ASSERT_NE(b3, nullptr);
    ASSERT_NE(b4, nullptr);

    // New block at position 2 has version=1 (fresh)
    EXPECT_EQ(b2->version, 1u);
    // Shifted blocks retain their original version=1
    EXPECT_EQ(b3->version, 1u);
    EXPECT_EQ(b4->version, 1u);
    // The shifted block now at position 3 is the same instance as old b2
    // (we can only verify count + version; identity is an implementation detail)
}

TEST_F(DynamicHashTableStateStoreTest, InsertBlockPreservesModifiedVersionsAfterShift)
{
    store_->addFile("f1", 3);
    store_->modifyBlock("f1", 2); // bump block 2 to version=2
    store_->modifyBlock("f1", 3); // bump block 3 to version=2

    store_->insertBlock("f1", 2); // insert before the modified block 2

    // After shift: old b2 (v=2) is now b3; old b3 (v=2) is now b4
    auto b3 = asVersioned(store_->getBlockMetadata("f1", 3));
    auto b4 = asVersioned(store_->getBlockMetadata("f1", 4));
    ASSERT_NE(b3, nullptr);
    ASSERT_NE(b4, nullptr);
    EXPECT_EQ(b3->version, 2u); // version preserved through shift
    EXPECT_EQ(b4->version, 2u);
}

TEST_F(DynamicHashTableStateStoreTest, InsertBlockRejectsMissingFile)
{
    EXPECT_THROW(store_->insertBlock("nope", 1), std::runtime_error);
}

// ============================================================================
// Maintenance: deleteBlock (shifts entries above down)
// ============================================================================
TEST_F(DynamicHashTableStateStoreTest, DeleteBlockAtEndShrinksCount)
{
    store_->addFile("f1", 3);
    store_->deleteBlock("f1", 3); // delete last
    EXPECT_EQ(store_->getBlockCount("f1"), 2u);
    EXPECT_THROW(store_->getBlockMetadata("f1", 3), std::runtime_error);
}

TEST_F(DynamicHashTableStateStoreTest, DeleteBlockInMiddleShiftsAboveDown)
{
    store_->addFile("f1", 3);
    store_->modifyBlock("f1", 3); // bump block 3 to version=2
    store_->deleteBlock("f1", 2); // delete middle

    // After shift: old block 3 (v=2) is now block 2
    EXPECT_EQ(store_->getBlockCount("f1"), 2u);
    auto b2 = asVersioned(store_->getBlockMetadata("f1", 2));
    ASSERT_NE(b2, nullptr);
    EXPECT_EQ(b2->version, 2u); // version preserved through shift
}

TEST_F(DynamicHashTableStateStoreTest, DeleteBlockRejectsOutOfRangeIndex)
{
    store_->addFile("f1", 1);
    EXPECT_THROW(store_->deleteBlock("f1", 2), std::runtime_error);
}

TEST_F(DynamicHashTableStateStoreTest, DeleteBlockRejectsMissingFile)
{
    EXPECT_THROW(store_->deleteBlock("nope", 1), std::runtime_error);
}

// ============================================================================
// Persistence tests removed — saveEntry/restoreEntry/saveAll/createEmpty
// have been deleted from DynamicPdpStateStore. Persistence is now handled
// by BlockMetadataRepository + FileStateRepository in the Application layer.
// ============================================================================
