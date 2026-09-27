cmake_minimum_required(VERSION 3.16)

# ============================================================================
# DHTDynamicAuditStrategy Tests
#
# Strategy-level tests: full pipeline, state store interface contract,
# real state store implementation, and engine state store lifecycle.
# These tests link against ChordAuditMatrixLib (CoreLib) + DHTDynamicAuditStrategy.
# ============================================================================

# cam_add_gtest lives in CoreLib's .cmake directory.
include(${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/CoreLib/.cmake/cam_add_gtest.cmake)

# Include roots:
#   - Strategy headers  (DHTDynamicAuditStrategy/...)
#   - CoreLib headers (ChordAuditMatrixLib/...): in-tree builds resolve these
#     through the canonical CoreLib target (lib/include). Standalone builds have
#     only the nested CoreLib checkout, so its include root is added there —
#     never in-tree, where it would shadow the canonical headers.
set(DHT_TEST_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)
if(CAM_STANDALONE)
    list(APPEND DHT_TEST_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/CoreLib/include)
endif()

# ── Full pipeline integration ──
cam_add_gtest(test_dht_dynamic_full_integration
    SOURCES test_dht_dynamic_full_integration.cpp
    LINK_LIBS DHTDynamicAuditStrategy
    INCLUDE_DIRS ${DHT_TEST_INCLUDE_DIRS}
    LABELS "DHTDynamicTests;scope:integration;purpose:regression"
)

# ── State store interface contract (mock-based) ──
cam_add_gtest(test_dht_dynamic_state_store_unit
    SOURCES test_dht_dynamic_state_store_unit.cpp
    LINK_LIBS DHTDynamicAuditStrategy
    INCLUDE_DIRS ${DHT_TEST_INCLUDE_DIRS}
    LABELS "DHTDynamicTests;scope:unit;purpose:regression"
)

# ── Real state store implementation ──
cam_add_gtest(test_dynamic_hash_table_state_store_unit
    SOURCES test_dynamic_hash_table_state_store_unit.cpp
    LINK_LIBS DHTDynamicAuditStrategy
    INCLUDE_DIRS ${DHT_TEST_INCLUDE_DIRS}
    LABELS "DHTDynamicTests;scope:unit;purpose:regression"
)

# ── Engine per-operation strategy/StateStore state ──
cam_add_gtest(test_engine_operation_state_unit
    SOURCES test_engine_operation_state_unit.cpp
    LINK_LIBS DHTDynamicAuditStrategy
    INCLUDE_DIRS ${DHT_TEST_INCLUDE_DIRS}
    LABELS "DHTDynamicTests;scope:unit;purpose:regression"
)
