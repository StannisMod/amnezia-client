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
    ../.. ../../mozilla/shared ../../.. ../../../common/logger ../../../service/server)
target_link_libraries(endpoint_protocol_compile PRIVATE Qt6::Core Qt6::Network Qt6::Qml)

add_executable(test_endpoint_ipc
    testEndpointIpc.cpp
    ../../mozilla/localsocketcontroller.cpp
    ../../mozilla/localsocketcontroller.h
    ../../mozilla/controllerimpl.h)
target_include_directories(test_endpoint_ipc PRIVATE
    ../../.. ../../mozilla/shared ../.. ../../../tests/linux-dns-cache/stubs)
target_link_libraries(test_endpoint_ipc PRIVATE Qt6::Core Qt6::Network Qt6::Test)
add_test(NAME EndpointIpc COMMAND test_endpoint_ipc)

add_executable(test_endpoint_dns testEndpointDns.cpp)
target_include_directories(test_endpoint_dns PRIVATE ../..)
target_link_libraries(test_endpoint_dns PRIVATE Qt6::Core Qt6::Network Qt6::Test)
add_test(NAME EndpointDns COMMAND test_endpoint_dns)

# Build the exact session/IPC driver used by installed-service migration tests.
add_executable(endpoint_acceptance_compile
    ../../../scripts/routing/service-probe/endpoint.cpp
    ../../mozilla/localsocketcontroller.cpp ../../mozilla/localsocketcontroller.h ../../mozilla/controllerimpl.h)
target_include_directories(endpoint_acceptance_compile PRIVATE
    ../.. ../../mozilla/shared ../../.. ../../../tests/linux-dns-cache/stubs)
target_compile_definitions(endpoint_acceptance_compile PRIVATE MZ_LINUX)
target_link_libraries(endpoint_acceptance_compile PRIVATE Qt6::Core Qt6::Network)
