cmake_minimum_required(VERSION 3.22)
project(AmneziaVpnEndpoints LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network Test Qml)
include(CTest)
add_executable(test_vpn_endpoints testVpnEndpoints.cpp)
target_link_libraries(test_vpn_endpoints PRIVATE Qt6::Core Qt6::Network Qt6::Test)
target_include_directories(test_vpn_endpoints PRIVATE ../..)
add_test(NAME VpnEndpoints COMMAND test_vpn_endpoints)

add_executable(test_vpn_endpoint_session testVpnEndpointSession.cpp)
target_link_libraries(test_vpn_endpoint_session PRIVATE Qt6::Core Qt6::Network Qt6::Test)
target_include_directories(test_vpn_endpoint_session PRIVATE ../..)
add_test(NAME VpnEndpointSession COMMAND test_vpn_endpoint_session)

# Compile the production protocol/IPC paths as well as the standalone policy.
# An OBJECT target avoids substituting fake protocol implementations merely to
# satisfy unrelated full-application link dependencies in this fast test lane.
add_library(endpoint_protocol_compile OBJECT
    ../../core/protocols/wireGuardProtocol.cpp
    ../../core/protocols/wireGuardProtocol.h
    ../../mozilla/localsocketcontroller.cpp
    ../../daemon/daemon.cpp
    ../../daemon/daemonlocalserverconnection.cpp)
target_include_directories(endpoint_protocol_compile PRIVATE
    ../.. ../../mozilla/shared ../../.. ../../../common/logger)
target_link_libraries(endpoint_protocol_compile PRIVATE Qt6::Core Qt6::Network Qt6::Qml)
