cmake_minimum_required(VERSION 3.25)
project(AmneziaDomainRoutingContract LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network Test)
include(CTest)
add_executable(test_domain_routing_contract
    testDomainRoutingConfig.cpp
    ../../core/utils/routeModes.h)
target_link_libraries(test_domain_routing_contract PRIVATE Qt6::Core Qt6::Network Qt6::Test)
target_include_directories(test_domain_routing_contract PRIVATE ../..)
add_test(NAME DomainRoutingContractTest COMMAND test_domain_routing_contract)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT ANDROID)
    add_executable(openvpn_ipv6_route_fixture openVpnIpv6RouteFixture.cpp)
    target_include_directories(openvpn_ipv6_route_fixture PRIVATE ../..)
    target_link_libraries(openvpn_ipv6_route_fixture PRIVATE Qt6::Core Qt6::Network)
endif()

# Export the production Qt-generated DNS policy for the real TUN acceptance.
add_executable(dns_policy_fixture dnsPolicyFixture.cpp)
target_link_libraries(dns_policy_fixture PRIVATE Qt6::Core)
