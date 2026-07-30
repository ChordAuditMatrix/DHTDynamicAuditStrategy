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
 * @file dynamic_hash_table_state_store.h
 * @brief Hash-table-based implementation of DynamicPdpStateStore
 * @details DynamicHashTableStateStore uses an unordered_map of
 *          BlockMetadataCollectionPtr for fast O(1) file lookup and
 *          map-based sparse block access. This is the default state store
 *          implementation for all dynamic PDP algorithms.
 *
 *          Each file is backed by an InMemoryBlockMetadataCollection,
 *          which uses std::map<size_t, shared_ptr<BlockMetadata>> for
 *          sparse indexed storage (mirrors the Tags/TagsPtr pattern).
 *
 *          Block indexing:
 *          - API methods use 1-based blockIndex
 *          - InMemoryBlockMetadataCollection uses 0-based indexing
 *          - Conversion: collection index = blockIndex - 1
 *
 * @author Dylan Liu
 * @version 4.0.0
 * @date 2026-07-30
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#ifndef DHTDYNAMIC_DYNAMIC_HASH_TABLE_STATE_STORE_H
#define DHTDYNAMIC_DYNAMIC_HASH_TABLE_STATE_STORE_H

#include "ChordAuditMatrixLib/implementations/audit/state_stores/dynamic_pdp_state_store.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/in_memory_block_metadata_collection.h"
#include "DHTDynamicAuditStrategy/state_stores/versioned_block_metadata.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace CAMatrix::Audit::Core {

/**
 * @class DynamicHashTableStateStore
 * @brief Hash-map based DynamicPdpStateStore implementation
 * @details Uses unordered_map<string, BlockMetadataCollectionPtr> for
 *          file storage. Each file is backed by an InMemoryBlockMetadataCollection
 *          which uses std::map<size_t, shared_ptr<BlockMetadata>> for sparse
 *          indexed block access (mirrors Tags/TagsPtr pattern).
 *
 *          Block indexing:
 *          - API methods use 1-based blockIndex
 *          - InMemoryBlockMetadataCollection uses 0-based indexing
 *          - Conversion: collection index = blockIndex - 1
 *
 *          The metadata factory defaults to VersionedBlockMetadata but can be
 *          injected via the constructor for algorithms that need custom
 *          BlockMetadata subclasses.
 *
 *          Not thread-safe.
 */
class DynamicHashTableStateStore final : public DynamicPdpStateStore {
public:
    /**
     * @brief Construct with a metadata factory
     * @param factory [IN] Function that creates a new BlockMetadata instance.
     *               Defaults to VersionedBlockMetadata.
     */
    explicit DynamicHashTableStateStore(
        InMemoryBlockMetadataCollection::BlockMetadataFactory factory =
        []() -> std::shared_ptr<BlockMetadata> {
            const auto now = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            return std::make_shared<VersionedBlockMetadata>(1, now);
        })
        : metadataFactory_(std::move(factory)) {}

    ~DynamicHashTableStateStore() override = default;

    // ── File-level operations ──

    /**
     * @brief Add a new empty file (no blocks)
     * @param fileId [IN] File identifier
     * @throws std::runtime_error If file already exists
     */
    void addFile(const std::string& fileId) override;

    /**
     * @brief Add a new file with pre-initialized block metadata
     * @param fileId [IN] File identifier
     * @param blockCount [IN] Number of blocks to initialize
     * @throws std::runtime_error If file already exists
     */
    void addFile(const std::string& fileId, std::size_t blockCount) override;

    /**
     * @brief Remove a file from the state store
     * @param fileId [IN] File identifier
     * @throws std::runtime_error If file does not exist
     */
    void removeFile(const std::string& fileId) override;

    /**
     * @brief Check if a file exists
     * @param fileId [IN] File identifier
     * @return bool, True if file exists
     */
    bool hasFile(const std::string& fileId) const override;
    /**
     * @brief List all file identifiers in the state store
     * @return vector<string>, File identifiers
     */
    std::vector<std::string> listFiles() const override;

    // ── Block-level queries ──

    /**
     * @brief Get metadata for a specific block
     * @param fileId [IN] File identifier
     * @param blockIndex [IN] Block index (1-based)
     * @return shared_ptr<BlockMetadata>, Block metadata
     */
    std::shared_ptr<BlockMetadata> getBlockMetadata(
        const std::string& fileId, std::size_t blockIndex) const override;

    /**
     * @brief Get the number of blocks in a file
     * @param fileId [IN] File identifier
     * @return std::size_t, Block count
     */
    std::size_t getBlockCount(const std::string& fileId) const override;

    /**
     * @brief Get the block metadata collection for a file
     * @param fileId [IN] File identifier
     * @return BlockMetadataCollectionPtr, Metadata collection
     */
    BlockMetadataCollectionPtr getBlockMetadataCollection(
        const std::string& fileId) const override;

    // ── Maintenance operations ──

    /**
     * @brief Modify an existing block (bump version + timestamp)
     * @param fileId [IN] File identifier
     * @param blockIndex [IN] Block index (1-based)
     */
    void modifyBlock(const std::string& fileId,
                     std::size_t blockIndex) override;

    /**
     * @brief Insert a new block at the specified index
     * @param fileId [IN] File identifier
     * @param blockIndex [IN] Block index to insert at (1-based)
     */
    void insertBlock(const std::string& fileId,
                     std::size_t blockIndex) override;

    /**
     * @brief Delete a block at the specified index
     * @param fileId [IN] File identifier
     * @param blockIndex [IN] Block index to delete (1-based)
     */
    void deleteBlock(const std::string& fileId,
                     std::size_t blockIndex) override;
    /**
     * @brief Set the block metadata collection for a file
     * @param fileId [IN] File identifier
     * @param collection [IN] Block metadata collection to assign
     */
    void setBlockMetadataCollection(const std::string& fileId, BlockMetadataCollectionPtr collection) override;

private:
    /** @brief File storage: fileId → BlockMetadataCollection */
    std::unordered_map<std::string, BlockMetadataCollectionPtr> files_;

    /** @brief Factory for creating BlockMetadata instances during deserialization */
    InMemoryBlockMetadataCollection::BlockMetadataFactory metadataFactory_;
};

} // namespace CAMatrix::Audit::Core

#endif // DHTDYNAMIC_DYNAMIC_HASH_TABLE_STATE_STORE_H
