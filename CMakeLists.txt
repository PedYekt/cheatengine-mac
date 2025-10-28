# Top-level CMake configuration for CheatEngine educational tool.
cmake_minimum_required(VERSION 3.20)

project(CheatEngine
    VERSION 0.1.0
    DESCRIPTION "Educational macOS memory introspection tool"
    LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    message(FATAL_ERROR "CheatEngine currently targets macOS (Darwin) platforms only.")
endif()

# Default to Debug builds when no build type is specified.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable verbose warnings and debug symbols for educational clarity.
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

# macOS-specific compiler flags for Mach API usage and debugging
if(APPLE)
    # Enable debugging symbols in all build types
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
    
    # Optimize for debugging and educational use
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer")
    
    # Enable additional warnings for system programming
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
endif()

set(CHEATENGINE_CORE_SOURCES
    src/core/errors.cpp
    src/core/application.cpp
    src/memory/value_types.cpp
    src/memory/memory_region.cpp
    src/memory/memory_scanner.cpp
    src/process/process_manager.cpp
    src/process/security_manager.cpp
    src/monitor/value_monitor.cpp
    src/writer/memory_writer.cpp)

add_library(cheatengine_core ${CHEATENGINE_CORE_SOURCES})

target_include_directories(cheatengine_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(cheatengine_core PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wimplicit-fallthrough
    )
endif()

# Ensure we can access Mach APIs and low-level Darwin interfaces.
target_compile_definitions(cheatengine_core PRIVATE
    _DARWIN_C_SOURCE
)

# Link required macOS frameworks for Mach VM APIs and security
if(APPLE)
    target_link_libraries(cheatengine_core PUBLIC
        "-framework Security"
        "-framework CoreFoundation"
    )
endif()

add_executable(cheatengine src/main.cpp)
target_link_libraries(cheatengine PRIVATE cheatengine_core)

# macOS code signing configuration for development and distribution
if(APPLE)
    # Set up code signing properties
    set_target_properties(cheatengine PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS "${CMAKE_SOURCE_DIR}/debug-entitlements.plist"
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Apple Development"
        XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ""
    )
    
    # Add post-build code signing for command line builds
    add_custom_command(TARGET cheatengine POST_BUILD
        COMMAND codesign --force --sign "Apple Development" 
                --entitlements "${CMAKE_SOURCE_DIR}/debug-entitlements.plist"
                "$<TARGET_FILE:cheatengine>"
        COMMENT "Code signing CheatEngine with entitlements"
        VERBATIM
    )
endif()

enable_testing()
add_subdirectory(tests)
