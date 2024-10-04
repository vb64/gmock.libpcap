cmake_minimum_required(VERSION 3.14)

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

set(DIR_MOCKPCAP "../../mockpcap")
set(COVERAGE_FLAGS "-fprofile-arcs -ftest-coverage")
set(TEST_FLAGS "${COVERAGE_FLAGS} -fPIC -O0")

set(CMAKE_CXX_FLAGS ${TEST_FLAGS})
set(CMAKE_C_FLAGS ${TEST_FLAGS})
set(CMAKE_EXE_LINKER_FLAGS "${COVERAGE_FLAGS}")

add_executable(
  sniffer_test
  ${DIR_MOCKPCAP}/mockpcap.h
  ${DIR_MOCKPCAP}/mockpcap.cpp
  sniffer_test.cpp
  ../source/sniffer.cpp
)
target_include_directories(
  sniffer_test PUBLIC
  "${gmock_SOURCE_DIR}/include"
  "${PROJECT_BINARY_DIR}"
)

target_link_libraries(
  sniffer_test
  GTest::gtest_main
  GTest::gmock_main
  pcap
)

include(GoogleTest)
gtest_discover_tests(sniffer_test)
