cmake_minimum_required(VERSION 3.14)
project(bob CXX)
set (CMAKE_CXX_STANDARD 17) # redis-plus-plus requires C++17

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
	SET(CXX_BOB_FLAGS "/arch:AVX2")
else ()
	SET(CXX_BOB_FLAGS "-Wunused-variable -mavx2")
endif()
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${CXX_BOB_FLAGS}")

# --- Fetch and configure dependencies ---
include(FetchContent)

# redis-plus-plus
FetchContent_Declare(
  redis-plus-plus
  GIT_REPOSITORY https://github.com/sewenew/redis-plus-plus.git
  GIT_TAG        1.3.8 # Using a specific tag for reproducibility
)
# redis-plus-plus specific options
set(REDIS_PLUS_PLUS_USE_HIREDIS_STATIC_LIB ON CACHE BOOL "" FORCE) # Avoid runtime dependency on hiredis
set(REDIS_PLUS_PLUS_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(REDIS_PLUS_PLUS_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(REDIS_PLUS_PLUS_BUILD_SHARED OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(redis-plus-plus)

# spdlog
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.12.0
)
FetchContent_MakeAvailable(spdlog)
include_directories(${spdlog_SOURCE_DIR}/include)
# cxxopts
FetchContent_Declare(
    cxxopts
    GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
    GIT_TAG        v3.1.1
)
FetchContent_MakeAvailable(cxxopts)
include_directories(${cxxopts_SOURCE_DIR}/include)

# gtest
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
FetchContent_MakeAvailable(googletest)

# zstd
FetchContent_Declare(
		zstd
		GIT_REPOSITORY https://github.com/facebook/zstd.git
		GIT_TAG v1.5.5
        SOURCE_SUBDIR build/cmake
)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd)
include_directories(${zstd_SOURCE_DIR}/lib)

# Choose the correct zstd target name depending on how it's defined.
if (TARGET libzstd_static)
  set(ZSTD_TARGET libzstd_static)
elseif (TARGET zstd::libzstd_static)
  set(ZSTD_TARGET zstd::libzstd_static)
elseif (TARGET zstd::libzstd_shared)
  set(ZSTD_TARGET zstd::libzstd_shared)
else()
  message(FATAL_ERROR "zstd target not found; expected libzstd_static or zstd::libzstd_static")
endif()

# rapidjson
FetchContent_Declare(
		rapidjson
		GIT_REPOSITORY https://github.com/Tencent/rapidjson.git
		GIT_TAG v1.1.0
)
set(RAPIDJSON_BUILD_DOC OFF CACHE BOOL "" FORCE)
set(RAPIDJSON_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(RAPIDJSON_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(rapidjson)
include_directories(${rapidjson_SOURCE_DIR}/include)

# Check for AVX2 support
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-mavx2" COMPILER_SUPPORTS_AVX2)
if (NOT COMPILER_SUPPORTS_AVX2)
	message(WARNING "AVX2 not supported by the compiler")
endif ()

# --- Project Sources ---
SET(FILES ${CMAKE_SOURCE_DIR}/connection.cpp
		  ${CMAKE_SOURCE_DIR}/parser.cpp
          ${CMAKE_SOURCE_DIR}/db.cpp
		  ${CMAKE_SOURCE_DIR}/Logger.cpp
		  ${CMAKE_SOURCE_DIR}/DataProcessors.cpp
		  ${CMAKE_SOURCE_DIR}/IOProcessor.cpp
		  ${CMAKE_SOURCE_DIR}/LoggingEventProcessor.cpp
		  ${CMAKE_SOURCE_DIR}/QubicServer.cpp
		  ${CMAKE_SOURCE_DIR}/QubicIndexer.cpp
		  ${CMAKE_SOURCE_DIR}/Config.cpp
		  ${CMAKE_SOURCE_DIR}/bob.cpp
		  ${CMAKE_SOURCE_DIR}/bobAPI.cpp
		  ${CMAKE_SOURCE_DIR}/GlobalVar.cpp
)

# Create a library from the source files to be shared between the main executable and tests
add_library(bob_lib STATIC ${FILES})
target_link_libraries(bob_lib PRIVATE redis++_static hiredis spdlog::spdlog cxxopts::cxxopts ${ZSTD_TARGET})


# --- Executable and Linking ---
ADD_EXECUTABLE(bob main.cpp)
target_link_libraries(bob PRIVATE bob_lib)


# --- Testing with Google Test ---
enable_testing()
include(GoogleTest)
include_directories(${CMAKE_SOURCE_DIR}/)
file(GLOB TEST_FILES "tests/*.cpp")
add_executable(bob_tests ${TEST_FILES})
target_link_libraries(bob_tests PRIVATE bob_lib gtest_main redis++_static hiredis spdlog::spdlog)
gtest_discover_tests(bob_tests)

# Copy configuration file after building bob
add_custom_command(
		TARGET bob POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${CMAKE_SOURCE_DIR}/default_config_bob.json
		${CMAKE_BINARY_DIR}/bob.json
)
