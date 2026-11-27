cmake_minimum_required(VERSION 3.25)
project(Ikev2DnsSessionTests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
if(MSVC)
    add_compile_options(/permissive- /Zc:__cplusplus)
endif()
enable_testing()
find_package(Qt6 REQUIRED COMPONENTS Core Test)
add_executable(test_ikev2_dns_session main.cpp)
target_link_libraries(test_ikev2_dns_session PRIVATE Qt6::Core Qt6::Test)
add_test(NAME ikev2_dns_session COMMAND test_ikev2_dns_session)
if(WIN32)
    find_package(Qt6 REQUIRED COMPONENTS Network)
    add_executable(test_windows_dns_policy_probe dnsPolicyProbe.cpp)
    target_link_libraries(test_windows_dns_policy_probe PRIVATE Qt6::Core ole32 oleaut32 wbemuuid)
    add_executable(test_windows_dns_policy dnsPolicy.cpp
        ../../client/platforms/windows/daemon/windowsdnspolicy.cpp)
    target_link_libraries(test_windows_dns_policy PRIVATE
        Qt6::Core Qt6::Network Qt6::Test iphlpapi advapi32 ole32 oleaut32 wbemuuid)
    target_compile_definitions(test_windows_dns_policy PRIVATE
        NOMINMAX UNICODE _UNICODE _WIN32_WINNT=0x0A00 WINVER=0x0A00)
    add_executable(test_ikev2_credential_file credential.cpp)
    target_link_libraries(test_ikev2_credential_file PRIVATE Qt6::Core Qt6::Test advapi32)
    add_test(NAME ikev2_credential_file COMMAND test_ikev2_credential_file)
    add_library(ikev2_dns_native_compile OBJECT
        ../../service/server/windowsikev2dns.cpp
        ../../client/platforms/windows/daemon/nativednsfirewall.cpp)
    target_include_directories(ikev2_dns_native_compile PRIVATE ../../client ../../service/server)
    target_compile_definitions(ikev2_dns_native_compile PRIVATE
        NOMINMAX UNICODE _UNICODE _WIN32_WINNT=0x0A00 WINVER=0x0A00)
    target_link_libraries(ikev2_dns_native_compile PRIVATE Qt6::Core Qt6::Network)
    add_executable(test_ikev2_dns_fence fence.cpp
        ../../client/platforms/windows/daemon/nativednsfirewall.cpp)
    target_include_directories(test_ikev2_dns_fence PRIVATE ../../client)
    target_link_libraries(test_ikev2_dns_fence PRIVATE Qt6::Core Qt6::Network Qt6::Test
        advapi32 fwpuclnt rpcrt4 ws2_32)
    add_test(NAME ikev2_dns_native_fence COMMAND test_ikev2_dns_fence)
    add_executable(test_deferred_service
        deferredService.cpp
        ../../service/src/qtservice.cpp
        ../../service/src/qtservice_win.cpp
        ../../service/src/qtservice.h
        ../../service/src/qtservice_p.h)
    target_include_directories(test_deferred_service PRIVATE ../../service/src)
    target_link_libraries(test_deferred_service PRIVATE Qt6::Core Qt6::Network advapi32 user32 shell32)
    add_executable(test_installer_deferred_service
        deferredService.cpp
        ../../service/src/qtservice.cpp
        ../../service/src/qtservice_win.cpp
        ../../service/src/qtservice.h
        ../../service/src/qtservice_p.h)
    target_compile_definitions(test_installer_deferred_service PRIVATE
        AMNEZIA_DEFERRED_SERVICE_NAME="AmneziaVPN-service")
    target_include_directories(test_installer_deferred_service PRIVATE ../../service/src)
    target_link_libraries(test_installer_deferred_service PRIVATE
        Qt6::Core Qt6::Network advapi32 user32 shell32)
endif()
