cmake_minimum_required(VERSION 3.16)
project(DHTDynamicAuditStrategy VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckCXXSourceCompiles)

# ==================== Options ====================
option(CAM_STANDALONE "Build as standalone project (on) or as part of ChordAuditMatrix (off)" ON)
option(CAM_BUILD_TESTS "Build tests" OFF)
option(CAM_GENERATE_DOCS "Generate Doxygen documentation" OFF)
# ==================== Sanitizer ====================
# Must be set BEFORE add_subdirectory(3rdparty/CoreLib) so that CoreLib's
# 3rdparty libraries (jsoncpp, spdlog, GmSSL) also get ASan instrumentation.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=address -fno-omit-frame-pointer")

    check_cxx_source_compiles("
        #include <stdlib.h>
        int main() {
            volatile int *p = (int*)malloc(sizeof(int));
            *p = 42;
            free((void*)p);
            return 0;
        }
    " HAS_ASAN)

    if(HAS_ASAN)
        message(STATUS "Sanitizer enabled for Debug build")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
        set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address")
    else()
        message(STATUS "Sanitizer not supported (compiler or linker)")
    endif()
endif()

# ==================== CoreLib Dependency ====================
# Disable CoreLib's own test registration to avoid NOT_BUILT test targets
# leaking into our ctest run. CoreLib's tests are maintained in the main
# ChordAuditMatrix monorepo, not here.
if(CAM_STANDALONE)
    set(CAM_BUILD_TESTS_SAVED "${CAM_BUILD_TESTS}")
    set(CAM_BUILD_TESTS OFF CACHE BOOL "CoreLib tests are in main project" FORCE)
    add_subdirectory(3rdparty/CoreLib EXCLUDE_FROM_ALL)
    set(CAM_BUILD_TESTS "${CAM_BUILD_TESTS_SAVED}" CACHE BOOL "Build and run tests" FORCE)
endif()

# ==================== Deploy Configuration ====================
# Include CAMDeploy to unify output directories (CMAKE_RUNTIME_OUTPUT_DIRECTORY,
# CMAKE_LIBRARY_OUTPUT_DIRECTORY, etc.) so that DLLs and test executables land
# in the same directory. Without this, gtest_discover_tests fails on Windows
# with exit code 0xc0000135 (DLL not found) because the test exe cannot locate
# DHTDynamicAuditStrategy.dll / ChordAuditMatrixLib.dll.
if(CAM_STANDALONE)
    include(${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/CoreLib/.cmake/CAMDeploy.cmake)
endif()

# ==================== Windows Export ====================
if(WIN32)
    add_compile_definitions(NOMINMAX _WINSOCKAPI_ _CRT_SECURE_NO_WARNINGS)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# ==================== Strategy Shared Library ====================
set(SOURCE
  source/strategy.cpp
  source/artifact_factory.cpp
  source/common.cpp
  source/params.cpp
  source/challenges.cpp
  source/generate_challenges.cpp
  source/generate_keys.cpp
  source/generate_proofs.cpp
  source/generate_tags.cpp
  source/initialize_algorithm.cpp
  source/maintain.cpp
  source/proves.cpp
  source/tags.cpp
  source/state_stores/dynamic_hash_table_state_store.cpp
  source/state_stores/versioned_block_metadata.cpp
)

if(NOT CAM_STANDALONE AND COMMAND cam_add_plugin)
    # In-tree: use the main project's plugin helper (sets output dir, RPATH, etc.)
    cam_add_plugin(${PROJECT_NAME} SOURCES ${SOURCE} PLUGIN_SUBDIR strategies)
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCE})
    target_link_libraries(${PROJECT_NAME} PRIVATE ChordAuditMatrixLib)
    target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        PREFIX "")
endif()


# ==================== Tests ====================
if(CAM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
# ==================== Doxygen ====================
if(CAM_GENERATE_DOCS)
    find_package(Doxygen QUIET)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_PROJECT_NAME ${PROJECT_NAME})
        set(DOXYGEN_PROJECT_BRIEF "Audit strategy module")
        set(DOXYGEN_OUTPUT_LANGUAGE "English")
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/.cmake/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        add_custom_target(${PROJECT_NAME}-docs ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM)
    else()
        message(WARNING "Doxygen not found; skipping ${PROJECT_NAME}-docs target. Install Doxygen or configure with -DCAM_GENERATE_DOCS=OFF.")
    endif()
endif()