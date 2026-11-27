cmake_minimum_required(VERSION 3.25)
project(NativeDnsTransactionTests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network Test)
enable_testing()
add_executable(test_native_dns_transaction
    testNativeDnsTransaction.cpp
    ../../client/daemon/interfaceconfig.cpp
    ../../client/daemon/interfaceconfig.h
    ../../client/mozilla/shared/ipaddress.cpp
    ../../client/daemon/dnsutils.h
    ../../client/daemon/nativeDnsGuard.h)
target_include_directories(test_native_dns_transaction PRIVATE ../../client ../../client/mozilla/shared)
target_link_libraries(test_native_dns_transaction PRIVATE Qt6::Core Qt6::Network Qt6::Test)
add_test(NAME NativeDnsTransaction COMMAND test_native_dns_transaction)
set_tests_properties(NativeDnsTransaction PROPERTIES TIMEOUT 30)
add_library(native_wg_dns_compile OBJECT
    ../../client/daemon/daemon.cpp
    ../../client/daemon/daemon.h
    ../../client/daemon/interfaceconfig.cpp
    ../../client/daemon/interfaceconfig.h)
target_include_directories(native_wg_dns_compile PRIVATE
    ../linux-dns-cache/stubs ../../client ../../client/mozilla/shared)
target_link_libraries(native_wg_dns_compile PRIVATE Qt6::Core Qt6::Network)
target_include_directories(native_wg_dns_compile BEFORE PRIVATE ../linux-dns-cache/stubs)
add_executable(test_daemon_lifecycle
    testDaemonLifecycle.cpp
    ../../client/daemon/dnsutils.h
    ../../client/daemon/wireguardutils.h
    ../../client/mozilla/shared/ipaddress.cpp)
target_include_directories(test_daemon_lifecycle PRIVATE
    ../linux-dns-cache/stubs ../../client ../../client/mozilla/shared)
target_link_libraries(test_daemon_lifecycle PRIVATE
    native_wg_dns_compile Qt6::Core Qt6::Network Qt6::Test)
add_test(NAME DaemonLifecycle COMMAND test_daemon_lifecycle)
set_tests_properties(DaemonLifecycle PROPERTIES TIMEOUT 30)
set(NATIVE_DNS_ARCHIVE "" CACHE FILEPATH "Existing native Xray archive/import library with the DNS overlay")
if(NATIVE_DNS_ARCHIVE OR TARGET amnezia::xray-bindings)
    if(TARGET amnezia::xray-bindings)
        set(NATIVE_DNS_LINK_TARGET amnezia::xray-bindings)
        file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/native-dns-runtime-$<CONFIG>.txt"
            CONTENT "$<TARGET_FILE:amnezia::xray-bindings>\n")
    else()
        get_filename_component(NATIVE_DNS_ARCHIVE_DIR "${NATIVE_DNS_ARCHIVE}" DIRECTORY)
        set(NATIVE_DNS_LINK_TARGET "${NATIVE_DNS_ARCHIVE}")
    endif()
    set(NATIVE_DNS_TLS_FIXTURE "" CACHE FILEPATH "Existing test-only selected TLS upstream")
    if(NOT NATIVE_DNS_TLS_FIXTURE)
        find_program(GO_EXECUTABLE go REQUIRED)
        set(NATIVE_DNS_TLS_FIXTURE "${CMAKE_CURRENT_BINARY_DIR}/native_dns_tls_fixture${CMAKE_EXECUTABLE_SUFFIX}")
        set(_dns_tls_source "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/routing/android-openvpn-dns/tls_upstream.go")
        add_custom_command(OUTPUT "${NATIVE_DNS_TLS_FIXTURE}"
            COMMAND "${CMAKE_COMMAND}" -E env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
                GOTELEMETRY=off GOMAXPROCS=2
                "${GO_EXECUTABLE}" build -mod=readonly -p=1 -trimpath
                "-ldflags=-s -w -buildid=" -o "${NATIVE_DNS_TLS_FIXTURE}" "${_dns_tls_source}"
            DEPENDS "${_dns_tls_source}" VERBATIM)
        add_custom_target(native_dns_tls_fixture_build DEPENDS "${NATIVE_DNS_TLS_FIXTURE}")
    elseif(NOT EXISTS "${NATIVE_DNS_TLS_FIXTURE}")
        message(FATAL_ERROR "Selected DNS service fixture requires its existing test-only TLS upstream")
    endif()
endif()
if(WIN32)
    add_library(native_dns_windows_compile OBJECT
        ../../client/platforms/windows/daemon/dnsutilswindows.cpp
        ../../client/platforms/windows/daemon/dnsutilswindows.h
        ../../client/platforms/windows/daemon/windowsdnsrecovery.cpp
        ../../client/platforms/windows/daemon/windowsdnspolicy.cpp)
    target_include_directories(native_dns_windows_compile PRIVATE
        ../linux-dns-cache/stubs ../../client ../../client/mozilla/shared)
    target_include_directories(native_dns_windows_compile BEFORE PRIVATE ../linux-dns-cache/stubs)
    target_compile_definitions(native_dns_windows_compile PRIVATE
        NOMINMAX UNICODE _UNICODE _WIN32_WINNT=0x0A00 WINVER=0x0A00)
    target_link_libraries(native_dns_windows_compile PRIVATE Qt6::Core Qt6::Network)
    if(NATIVE_DNS_ARCHIVE OR TARGET amnezia::xray-bindings)
        add_executable(test_native_dns_windows_service testNativeDnsWindowsService.cpp
            ../../client/platforms/windows/daemon/nativednsfirewall.cpp
            ../../client/platforms/windows/daemon/windowsdnsrecovery.cpp
            ../../client/platforms/windows/daemon/windowsdnspolicy.cpp
            ../../client/platforms/windows/daemon/dnsutilswindows.cpp
            ../../client/platforms/windows/daemon/dnsutilswindows.h
            ../../client/daemon/dnsutils.h
            ../../service/server/nativednsservice.cpp)
        target_include_directories(test_native_dns_windows_service PRIVATE
            ../linux-dns-cache/stubs ../../client ../../client/mozilla/shared
            ../../service/server "${NATIVE_DNS_ARCHIVE_DIR}")
        target_include_directories(test_native_dns_windows_service BEFORE PRIVATE ../linux-dns-cache/stubs)
        set_target_properties(test_native_dns_windows_service PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}")
        target_compile_definitions(test_native_dns_windows_service PRIVATE
            NOMINMAX UNICODE _UNICODE _WIN32_WINNT=0x0A00 WINVER=0x0A00
            AMNEZIA_DNS_TLS_FIXTURE_PATH="${NATIVE_DNS_TLS_FIXTURE}")
        target_link_libraries(test_native_dns_windows_service PRIVATE
            Qt6::Core Qt6::Network Qt6::Test ${NATIVE_DNS_LINK_TARGET}
            iphlpapi advapi32 ws2_32 fwpuclnt rpcrt4 ole32 oleaut32 wbemuuid crypt32)
        if(TARGET native_dns_tls_fixture_build)
            add_dependencies(test_native_dns_windows_service native_dns_tls_fixture_build)
        endif()
        add_test(NAME NativeDnsWindowsService COMMAND test_native_dns_windows_service)
    endif()
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(Qt6 REQUIRED COMPONENTS DBus)
    add_library(native_dns_linux_compile OBJECT
        ../../client/platforms/linux/daemon/linuxdnsrecovery.cpp
        ../../client/platforms/linux/daemon/dnsutilslinux.cpp
        ../../client/platforms/linux/daemon/dnsutilslinux.h
        ../../client/platforms/linux/daemon/dbustypeslinux.h)
    target_include_directories(native_dns_linux_compile PRIVATE
        ../linux-dns-cache/stubs ../../client ../../client/platforms/linux/daemon)
    target_link_libraries(native_dns_linux_compile PRIVATE Qt6::Core Qt6::Network Qt6::DBus)
    target_include_directories(native_dns_linux_compile BEFORE PRIVATE ../linux-dns-cache/stubs)
    if(NATIVE_DNS_ARCHIVE OR TARGET amnezia::xray-bindings)
        find_package(Threads REQUIRED)
        add_executable(test_native_dns_service
            testNativeDnsService.cpp
            ../../client/platforms/linux/daemon/linuxdnsrecovery.cpp
            ../../client/platforms/linux/daemon/dnsutilslinux.cpp
            ../../client/platforms/linux/daemon/dnsutilslinux.h
            ../../service/server/nativednsservice.cpp
            ../../service/server/openvpndnssession.cpp
            ../../service/server/openvpndnsselection.cpp
            ../../client/core/utils/managementServer.cpp
            ../../client/daemon/dnsutils.h)
        target_include_directories(test_native_dns_service PRIVATE
            ../linux-dns-cache/stubs ../../client/mozilla/shared
            ../../client ../../service/server "${NATIVE_DNS_ARCHIVE_DIR}")
        target_include_directories(test_native_dns_service BEFORE PRIVATE ../linux-dns-cache/stubs)
        target_link_libraries(test_native_dns_service PRIVATE Qt6::Core Qt6::Network Qt6::Test
            Qt6::DBus
            ${NATIVE_DNS_LINK_TARGET} Threads::Threads ${CMAKE_DL_LIBS} m resolv)
        if(TARGET native_dns_tls_fixture_build)
            add_dependencies(test_native_dns_service native_dns_tls_fixture_build)
        endif()
        target_compile_definitions(test_native_dns_service PRIVATE
            AMNEZIA_DNS_TLS_FIXTURE_PATH="${NATIVE_DNS_TLS_FIXTURE}")
        add_test(NAME NativeDnsService COMMAND test_native_dns_service)
        set_tests_properties(NativeDnsService PROPERTIES TIMEOUT 30)
    endif()
endif()
