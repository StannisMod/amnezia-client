cmake_minimum_required(VERSION 3.25)
project(LinuxDnsCacheTests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network Test)
enable_testing()
add_executable(test_linux_dns_cache testLinuxDnsCache.cpp)
target_link_libraries(test_linux_dns_cache PRIVATE Qt6::Core Qt6::Test)
add_test(NAME LinuxDnsCache COMMAND test_linux_dns_cache)
set_tests_properties(LinuxDnsCache PROPERTIES TIMEOUT 30)

# Exercise the production route monitor inside an isolated network namespace.
add_executable(test_linux_exclusion_routes
    testLinuxExclusionRoutes.cpp
    ../../client/platforms/linux/daemon/linuxroutemonitor.cpp
    ../../client/platforms/linux/daemon/linuxroutemonitor.h
    ../../client/mozilla/shared/ipaddress.cpp
)
target_include_directories(test_linux_exclusion_routes PRIVATE
    stubs
    ../../client/mozilla/shared
    ../../client/platforms/linux/daemon
)
target_link_libraries(test_linux_exclusion_routes PRIVATE Qt6::Core Qt6::Network Qt6::Test)
add_test(NAME LinuxExclusionRoutes COMMAND bash
    ${CMAKE_CURRENT_SOURCE_DIR}/run-route-tests.sh $<TARGET_FILE:test_linux_exclusion_routes>)
set_tests_properties(LinuxExclusionRoutes PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)
