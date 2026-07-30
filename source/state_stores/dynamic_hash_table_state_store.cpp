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
 * @file dynamic_hash_table_state_store.cpp
 * @brief Hash-table-based implementation of DynamicPdpStateStore
 * @details Uses unordered_map<string, InMemoryBlockMetadataCollectionPtr> for
 *          file storage. Each file is backed by an InMemoryBlockMetadataCollection
 *          which uses std::map<size_t, shared_ptr<BlockMetadata>> for sparse
 *          indexed block access (mirrors Tags/TagsPtr pattern).
 *
 *          Block indexing:
 *          - API methods use 1-based blockIndex
 *          - InMemoryBlockMetadataCollection uses 0-based indexing
 *          - Conversion: collection index = blockIndex - 1
 *
 *          Persistence uses cereal BinaryArchive to serialize/restore
 *          InMemoryBlockMetadataCollection data.
 *
 * @author Dylan Liu
 * @version 3.0.0
 * @date 2026-07-10
 * @copyright Copyright (C) 2021 - 2026, Dylan Liu
 */

#include "DHTDynamicAuditStrategy/state_stores/dynamic_hash_table_state_store.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/in_memory_block_metadata_collection.h"

#include <stdexcept>
#include <utility>
#include <vector>

namespace CAMatrix::Audit::Strategies::DHTDynamic {

// ── File-level operations ──

void DynamicHashTableStateStore::addFile(const std::string& fileId)
{
    if (files_.find(fileId) != files_.end()) {
        throw std::runtime_error("DynamicHashTableStateStore::addFile: file '" +
            fileId + "' already exists");
    }
    auto collection = std::make_shared<InMemoryBlockMetadataCollection>(metadataFactory_);
    files_[fileId] = collection;
}

void DynamicHashTableStateStore::addFile(const std::string& fileId, std::size_t blockCount)
{
    if (files_.find(fileId) != files_.end()) {
        throw std::runtime_error("DynamicHashTableStateStore::addFile: file '" +
            fileId + "' already exists");
    }
    if (blockCount == 0) {
        throw std::invalid_argument("DynamicHashTableStateStore::addFile: blockCount must be > 0");
    }

    auto collection = std::make_shared<InMemoryBlockMetadataCollection>(metadataFactory_);

    // Pre-initialize blockCount entries via the collection's factory
    // Collection uses 0-based indexing; API uses 1-based blockIndex
    for (std::size_t i = 0; i < blockCount; ++i) {
        collection->set(i, collection->createInitMetadata());
    }

    files_[fileId] = collection;
}

void DynamicHashTableStateStore::removeFile(const std::string& fileId)
{
    auto it = files_.find(fileId);
    if (it == files_.end()) {
        throw std::runtime_error("DynamicHashTableStateStore::removeFile: file '" +
            fileId + "' does not exist");
    }
    files_.erase(it);
}

bool DynamicHashTableStateStore::hasFile(const std::string& fileId) const
{
    return files_.find(fileId) != files_.end();
}

// ── Block-level queries ──

std::shared_ptr<BlockMetadata>
DynamicHashTableStateStore::getBlockMetadata(
    const std::string& fileId, std::size_t blockIndex) const
{
    auto it = files_.find(fileId);
    if (it == files_.end()) {
        throw std::runtime_error("DynamicHashTableStateStore::getBlockMetadata: file '" +
            fileId + "' does not exist");
    }

    // blockIndex is 1-based, collection is 0-based
    const std::size_t collIdx = blockIndex - 1;
    if (!it->second->contains(collIdx)) {
        throw std::runtime_error(
            "DynamicHashTableStateStore::getBlockMetadata: blockIndex " +
            std::to_string(blockIndex) + " out of range for file '" + fileId +
            "' (block count: " + std::to_string(it->second->size()) + ")");
    }

    auto meta = it->second->getByIndex(collIdx);
    if (!meta) {
        throw std::runtime_error(
            "DynamicHashTableStateStore::getBlockMetadata: block at index " +
            std::to_string(blockIndex) + " is null for file '" + fileId + "'");
    }

    return meta;
}

std::size_t DynamicHashTableStateStore::getBlockCount(const std::string& fileId) const
{
    auto it = files_.find(fileId);
    if (it == files_.end()) {
        throw std::runtime_error("DynamicHashTableStateStore::getBlockCount: file '" +
            fileId + "' does not exist");
    }
    return it->second->size();
}

BlockMetadataCollectionPtr
DynamicHashTableStateStore::getBlockMetadataCollection(
    const std::string& fileId) const
{
    auto it = files_.find(fileId);
    if (it == files_.end()) {
        throw std::runtime_error(
            "DynamicHashTableStateStore::getBlockMetadataCollection: file '" +
            fileId + "' does not exist");
    }
    return it->second;
}

// ── Maintenance operations ──

void DynamicHashTableStateStore::modifyBlock(
    const std::string& fileId,
    std::size_t blockIndex)
{
    auto it = files_.find(fileId);
    if (it == files_.end()) {
        throw std::runtime_error("DynamicHashTableStateStore::modifyBlock: file '" +
            fileId + "' does not exist");
    }

    const std::size_t collIdx = blockIndex - 1;
    if (!it->second->contains(collIdx)) {
        throw std::runtime_error(
            "DynamicHashTableStateStore::modifyBlock: blockIndex " +
            std::to_string(blockIndex) + " out of range for file '" + fileId + "'");
    }

    auto existing = it->second->getByIndex(collIdx);
    if (!existing) {
        throw std::runtime_error(
            "DynamicHashTableStateStore::modifyBlock: block at index " +
            std::to_string(blockIndex) + " is null for file '" + fileId +
            "'; use insertBlock to create new entries");
    }

    // Bump metadata in-place: increment version and refresh timestamp
    existing->bump();
}

void DynamicHashTableStateStore::insertBlock(
    const std::string& fileId,
    std::size_t blockIndex)
{
    auto it = files_.find(fileId);
    if (it == files_.end()) {
        throw std::runtime_error("DynamicHashTableStateStore::insertBlock: file '" +
                                 fileId + "' does not exist");
    }

    const std::size_t collIdx = blockIndex - 1;

    // For sparse map-based storage, we need to shift existing entries at collIdx and above
    // by incrementing their indices by 1, then set the new metadata at collIdx.
    auto& collection = it->second;

    // Create metadata via the collection's factory (version=1, timestamp=now)
    auto metadata = metadataFactory_();

    // Collect entries at collIdx or above that need to be shifted
    std::vector<std::pair<std::size_t, std::shared_ptr<BlockMetadata>>> toShift;
    for (auto entryIt = collection->begin(); entryIt != collection->end(); ++entryIt) {
        if (entryIt->first >= collIdx) {
            toShift.emplace_back(entryIt->first, entryIt->second);
        }
    }

    // Remove entries that will be shifted, then re-insert at index+1
    // We use clear + re-insert approach since BlockMetadataCollection has no erase()
    if (!toShift.empty()) {
        // Save all entries below collIdx (they stay unchanged)
        std::vector<std::pair<std::size_t, std::shared_ptr<BlockMetadata>>> below;
        for (auto entryIt = collection->begin(); entryIt != collection->end(); ++entryIt) {
            if (entryIt->first < collIdx) {
                below.emplace_back(entryIt->first, entryIt->second);
            }
        }

        // Clear and rebuild: entries below collIdx stay, shifted entries get index+1
        collection->clear();
        for (auto& [idx, meta] : below) {
            collection->set(idx, std::move(meta));
        }
        for (auto& [idx, meta] : toShift) {
            collection->set(idx + 1, std::move(meta));
        }
    }

    // Set the new metadata at collIdx
    collection->set(collIdx, std::move(metadata));
}

void DynamicHashTableStateStore::deleteBlock(
    const std::string& fileId, std::size_t blockIndex)
{
    auto it = files_.find(fileId);
    if (it == files_.end()) {
        throw std::runtime_error("DynamicHashTableStateStore::deleteBlock: file '" +
            fileId + "' does not exist");
    }

    const std::size_t collIdx = blockIndex - 1;
    auto& collection = it->second;

    if (!collection->contains(collIdx)) {
        throw std::runtime_error(
            "DynamicHashTableStateStore::deleteBlock: blockIndex " +
            std::to_string(blockIndex) + " out of range for file '" + fileId + "'");
    }

    // For sparse map-based storage, we need to:
    // 1. Remove the entry at collIdx
    // 2. Shift entries above collIdx down by 1
    // Use clear + re-insert approach since BlockMetadataCollection has no erase()

    // Collect entries below collIdx (stay unchanged)
    std::vector<std::pair<std::size_t, std::shared_ptr<BlockMetadata>>> below;
    // Collect entries above collIdx (shift down by 1)
    std::vector<std::pair<std::size_t, std::shared_ptr<BlockMetadata>>> above;
    for (auto entryIt = collection->begin(); entryIt != collection->end(); ++entryIt) {
        if (entryIt->first < collIdx) {
            below.emplace_back(entryIt->first, entryIt->second);
        } else if (entryIt->first > collIdx) {
            above.emplace_back(entryIt->first, entryIt->second);
        }
        // entryIt->first == collIdx is the one being deleted — skip it
    }

    // Clear and rebuild
    collection->clear();
    for (auto& [idx, meta] : below) {
        collection->set(idx, std::move(meta));
    }
    for (auto& [idx, meta] : above) {
        collection->set(idx - 1, std::move(meta));
    }
}

// ── File listing ──

std::vector<std::string> DynamicHashTableStateStore::listFiles() const
{
    std::vector<std::string> result;
    result.reserve(files_.size());
    for (const auto& [fileId, _] : files_) {
        result.push_back(fileId);
    }
    return result;
}

// ── BlockMetadataCollection injection ──

void DynamicHashTableStateStore::setBlockMetadataCollection(
    const std::string& fileId, BlockMetadataCollectionPtr collection)
{
    auto it = files_.find(fileId);
    if (it == files_.end()) {
        throw std::runtime_error(
            "DynamicHashTableStateStore::setBlockMetadataCollection: file '" +
            fileId + "' does not exist");
    }
    it->second = std::move(collection);
}

} // namespace CAMatrix::Audit::Strategies::DHTDynamic
