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
 * @file test_state_store_lifecycle_unit.cpp
 * @brief Tests AuditEngine StateStore lifecycle with real DHTDynamic strategy.
 * @date 2026-07-30
 */

#include "ChordAuditMatrixLib/interfaces/audit/engine.h"
#include "ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/dynamic_pdp_state_store.h"
#include "DHTDynamicAuditStrategy/state_stores/dynamic_hash_table_state_store.h"
#include "DHTDynamicAuditStrategy/strategy.h"

#include <gtest/gtest.h>

using CAMatrix::Audit::Core::AuditEngine;
using CAMatrix::Audit::Core::AuditEngineFactory;
using CAMatrix::Audit::Core::DynamicAuditStrategy;
using CAMatrix::Audit::Core::DynamicPdpStateStore;
using CAMatrix::Audit::Strategies::DHTDynamicAuditStrategy;
using CAMatrix::Audit::Strategies::DHTDynamic::DynamicHashTableStateStore;

// ═══════════════════════════════════════════════════════════════
// Default mode: lazy creation via createStateStore
// ═══════════════════════════════════════════════════════════════

TEST(StateStoreLifecycleTest, DefaultModeLazyCreateOnGetStateStore) {
    auto& engine = AuditEngineFactory::getInstance();
    auto strategy = std::make_shared<DHTDynamicAuditStrategy>();
    engine.setStrategy(strategy);

    auto store = engine.getStateStore();
    EXPECT_NE(store, nullptr);
}

TEST(StateStoreLifecycleTest, DefaultModeClearsStoreOnSetStrategy) {
    auto& engine = AuditEngineFactory::getInstance();
    auto strategy1 = std::make_shared<DHTDynamicAuditStrategy>();
    engine.setStrategy(strategy1);

    auto store1 = engine.getStateStore();
    ASSERT_NE(store1, nullptr);

    auto strategy2 = std::make_shared<DHTDynamicAuditStrategy>();
    engine.setStrategy(strategy2);

    auto store2 = engine.getStateStore();
    ASSERT_NE(store2, nullptr);
    EXPECT_NE(store1.get(), store2.get());
}

// ═══════════════════════════════════════════════════════════════
// External injection mode
// ═══════════════════════════════════════════════════════════════

TEST(StateStoreLifecycleTest, ExternalInjectionPreservesAcrossSetStrategy) {
    auto& engine = AuditEngineFactory::getInstance();
    auto strategy1 = std::make_shared<DHTDynamicAuditStrategy>();
    engine.setStrategy(strategy1);

    auto externalStore = std::make_shared<DynamicHashTableStateStore>();
    engine.setStateStore(externalStore);

    auto strategy2 = std::make_shared<DHTDynamicAuditStrategy>();
    engine.setStrategy(strategy2);

    auto store = engine.getStateStore();
    EXPECT_EQ(store.get(), externalStore.get());
}

TEST(StateStoreLifecycleTest, ExternalInjectionRejectsNullptr) {
    auto& engine = AuditEngineFactory::getInstance();
    EXPECT_THROW(engine.setStateStore(nullptr), std::logic_error);
}

// ═══════════════════════════════════════════════════════════════
// createStateStore direct
// ═══════════════════════════════════════════════════════════════

TEST(StateStoreLifecycleTest, CreateStateStoreReturnsNewInstance) {
    auto& engine = AuditEngineFactory::getInstance();
    auto strategy = std::make_shared<DHTDynamicAuditStrategy>();
    engine.setStrategy(strategy);

    auto store1 = engine.createStateStore();
    auto store2 = engine.createStateStore();
    EXPECT_NE(store1, nullptr);
    EXPECT_NE(store2, nullptr);
    EXPECT_NE(store1.get(), store2.get());
}
