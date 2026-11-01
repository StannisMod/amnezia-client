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
add_test(NAME DomainRoutingContractTest COMMAND test_domain_routing_contract)
