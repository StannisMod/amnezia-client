cmake_minimum_required(VERSION 3.25)
project(OpenVpnDnsSessionTests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network Test)
enable_testing()
add_executable(test_openvpn_dns_session
    testOpenVpnDnsSession.cpp
    ../../service/server/openvpndnssession.cpp
    ../../service/server/openvpndnsselection.cpp
    ../../client/core/utils/managementServer.cpp)
target_include_directories(test_openvpn_dns_session PRIVATE ../../client ../../service/server)
target_link_libraries(test_openvpn_dns_session PRIVATE Qt6::Core Qt6::Network Qt6::Test)
add_test(NAME OpenVpnDnsSession COMMAND test_openvpn_dns_session)
set_tests_properties(OpenVpnDnsSession PROPERTIES TIMEOUT 20)
