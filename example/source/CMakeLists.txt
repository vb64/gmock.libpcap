cmake_minimum_required(VERSION 3.15)
set(DIR_MOCKPCAP "../../mockpcap")

add_executable(
  sniffer
  main.cpp
  sniffer.cpp
  ${DIR_MOCKPCAP}/libpcap.cpp
)

target_include_directories(
  sniffer PUBLIC
  "${PROJECT_BINARY_DIR}"
)

target_link_libraries(sniffer pcap)
