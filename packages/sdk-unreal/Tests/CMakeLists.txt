# Standalone build of the Auth4Core protocol core and its tests. Unreal never reads this file. The
# flags mirror Unreal's defaults that matter for the core: C++17, no exceptions, warnings as errors.
# Run through Tests/run-tests.mjs, which also starts the mock server.
cmake_minimum_required(VERSION 3.16)
project(auth4_unreal_core_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../Source/Auth4Core")

add_executable(auth4_core_tests
  "${CORE_DIR}/Private/Auth4Client.cpp"
  "${CORE_DIR}/Private/Auth4Json.cpp"
  "${CORE_DIR}/Private/Auth4Url.cpp"
  TestSupport.cpp
  ClientTests.cpp
  MockServerTests.cpp)

target_include_directories(auth4_core_tests PRIVATE "${CORE_DIR}/Public" "${CORE_DIR}/Private")

if(MSVC)
  string(REGEX REPLACE "/EH[a-z]+" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  target_compile_options(auth4_core_tests PRIVATE /W4 /WX /EHs-c- /permissive- /utf-8)
  target_compile_definitions(auth4_core_tests PRIVATE _HAS_EXCEPTIONS=0 _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX)
else()
  target_compile_options(auth4_core_tests PRIVATE -Wall -Wextra -Wshadow -Werror -fno-exceptions)
endif()

if(WIN32)
  target_link_libraries(auth4_core_tests PRIVATE ws2_32)
endif()
