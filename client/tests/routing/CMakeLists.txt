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
add_executable(test_mac_openvpn_ipv6_policy testMacOpenVpnIpv6Policy.cpp)
target_link_libraries(test_mac_openvpn_ipv6_policy PRIVATE Qt6::Core Qt6::Network Qt6::Test)
add_test(NAME MacOpenVpnIpv6PolicyTest COMMAND test_mac_openvpn_ipv6_policy)

if(WIN32)
    add_executable(windows_openvpn_ipv6_api_compile windowsOpenVpnIpv6Compile.cpp)
    target_link_libraries(windows_openvpn_ipv6_api_compile PRIVATE iphlpapi ws2_32)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND NOT MACOS_NE)
    add_executable(mac_openvpn_ipv6_api_compile macOpenVpnIpv6Compile.cpp)
    target_link_libraries(mac_openvpn_ipv6_api_compile PRIVATE Qt6::Core Qt6::Network)
endif()
if((CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT ANDROID) OR WIN32
   OR (CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND NOT MACOS_NE))
    add_executable(openvpn_ipv6_route_fixture openVpnIpv6RouteFixture.cpp)
    target_include_directories(openvpn_ipv6_route_fixture PRIVATE ../..)
    target_link_libraries(openvpn_ipv6_route_fixture PRIVATE Qt6::Core Qt6::Network)
    if(WIN32)
        target_link_libraries(openvpn_ipv6_route_fixture PRIVATE iphlpapi ws2_32)
    endif()
    set(_fixture_ipc_default OFF)
    if(WIN32 OR (CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND NOT MACOS_NE)
       OR (TARGET Qt6::RemoteObjects AND TARGET Qt6::Core5Compat))
        set(_fixture_ipc_default ON)
    endif()
    option(AMNEZIA_ROUTE_FIXTURE_IPC "Build the service IPC acceptance driver" ${_fixture_ipc_default})
    if(AMNEZIA_ROUTE_FIXTURE_IPC)
        find_package(Qt6 REQUIRED COMPONENTS RemoteObjects Core5Compat)
        qt_add_repc_replicas(openvpn_ipv6_route_fixture ../../../ipc/ipc_interface.rep ../../../ipc/ipc_process_interface.rep)
        target_include_directories(openvpn_ipv6_route_fixture PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ../../../ipc ../../mozilla/shared)
        target_compile_definitions(openvpn_ipv6_route_fixture PRIVATE AMNEZIA_ROUTE_FIXTURE_IPC)
        target_link_libraries(openvpn_ipv6_route_fixture PRIVATE Qt6::RemoteObjects Qt6::Core5Compat)
    endif()
endif()

# Native acceptance is opt-in because it installs routes through the actual
# service. The caller must provision an isolated VM and its Linux fixture;
# ordinary desktop unit tests never change the developer machine's routes.
if(WIN32)
    set(AMNEZIA_WINDOWS_OPENVPN_FIXTURE_URL "" CACHE STRING "Owned VM OpenVPN fixture URL")
    set(AMNEZIA_WINDOWS_OPENVPN_VM_NAME "" CACHE STRING "Disposable Windows VM computer name")
    set(AMNEZIA_WINDOWS_OPENVPN_CASES "" CACHE STRING "Profile names provided by the fixture")
    if(AMNEZIA_WINDOWS_OPENVPN_FIXTURE_URL)
        if(NOT AMNEZIA_ROUTE_FIXTURE_IPC OR NOT AMNEZIA_WINDOWS_OPENVPN_VM_NAME OR NOT AMNEZIA_WINDOWS_OPENVPN_CASES)
            message(FATAL_ERROR "Native OpenVPN acceptance requires IPC, an explicit owned VM name, and profile cases")
        endif()
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        set(_openvpn_acceptance "${CMAKE_CURRENT_SOURCE_DIR}/../../../scripts/routing/run_windows_openvpn_acceptance.py")
        set(_openvpn_cases full include exclude api-full legacy-full legacy-include legacy-exclude legacy-export legacy-api stale-full)
        foreach(_case IN LISTS AMNEZIA_WINDOWS_OPENVPN_CASES)
            if(NOT _case IN_LIST _openvpn_cases)
                message(FATAL_ERROR "Unknown Windows OpenVPN profile case: ${_case}")
            endif()
            add_test(NAME WindowsOpenVpnProfile_${_case}
                COMMAND "${Python3_EXECUTABLE}" "${_openvpn_acceptance}"
                --fixture-url "${AMNEZIA_WINDOWS_OPENVPN_FIXTURE_URL}"
                --ipc-driver "$<TARGET_FILE:openvpn_ipv6_route_fixture>"
                --work "${CMAKE_CURRENT_BINARY_DIR}/openvpn-acceptance"
                --owned-vm-name "${AMNEZIA_WINDOWS_OPENVPN_VM_NAME}" --case "${_case}")
            set_tests_properties(WindowsOpenVpnProfile_${_case} PROPERTIES
                RUN_SERIAL TRUE TIMEOUT 180 LABELS "native;installed-service;openvpn"
                ENVIRONMENT "AMNEZIA_IPV6_LAB=owned-windows-vm")
        endforeach()
        if("full" IN_LIST AMNEZIA_WINDOWS_OPENVPN_CASES)
            add_test(NAME WindowsNativeIpv6Preference
                COMMAND "${Python3_EXECUTABLE}" "${_openvpn_acceptance}"
                --fixture-url "${AMNEZIA_WINDOWS_OPENVPN_FIXTURE_URL}"
                --ipc-driver "$<TARGET_FILE:openvpn_ipv6_route_fixture>"
                --work "${CMAKE_CURRENT_BINARY_DIR}/openvpn-acceptance"
                --owned-vm-name "${AMNEZIA_WINDOWS_OPENVPN_VM_NAME}" --case full --native-ipv6-preference)
            set_tests_properties(WindowsNativeIpv6Preference PROPERTIES
                RUN_SERIAL TRUE TIMEOUT 180 LABELS "native;installed-service;ipv6"
                ENVIRONMENT "AMNEZIA_IPV6_LAB=owned-windows-vm")
        endif()
        if("include" IN_LIST AMNEZIA_WINDOWS_OPENVPN_CASES)
            add_test(NAME WindowsOpenVpnRoutePreservation
                COMMAND "${Python3_EXECUTABLE}" "${_openvpn_acceptance}"
                --fixture-url "${AMNEZIA_WINDOWS_OPENVPN_FIXTURE_URL}"
                --ipc-driver "$<TARGET_FILE:openvpn_ipv6_route_fixture>"
                --work "${CMAKE_CURRENT_BINARY_DIR}/openvpn-acceptance"
                --owned-vm-name "${AMNEZIA_WINDOWS_OPENVPN_VM_NAME}" --case include --route-updates)
            set_tests_properties(WindowsOpenVpnRoutePreservation PROPERTIES
                RUN_SERIAL TRUE TIMEOUT 180 LABELS "native;installed-service;openvpn"
                ENVIRONMENT "AMNEZIA_IPV6_LAB=owned-windows-vm")
        endif()
    endif()
endif()

# Export the production Qt-generated DNS policy for the real TUN acceptance.
add_executable(dns_policy_fixture dnsPolicyFixture.cpp)
target_link_libraries(dns_policy_fixture PRIVATE Qt6::Core)
