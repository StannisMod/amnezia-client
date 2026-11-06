cmake_minimum_required(VERSION 3.22)
project(StabilityNetworkEvents LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network DBus)
get_filename_component(REPO "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)
add_executable(network-events main.cpp
 "${REPO}/client/platforms/linux/linuxnetworkwatcherworker.cpp"
 "${REPO}/client/platforms/linux/linuxnetworkwatcherworker.h")
target_include_directories(network-events PRIVATE
 "${CMAKE_CURRENT_SOURCE_DIR}/stubs"
 "${REPO}/client/mozilla/shared"
 "${REPO}/client/platforms/linux")
target_link_libraries(network-events PRIVATE Qt6::Core Qt6::Network Qt6::DBus)
