cmake_minimum_required(VERSION 3.25)
project(NativeDnsDesktopLifecycle LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network Test)
enable_testing()
if(NOT WIN32 AND NOT APPLE)
    message(FATAL_ERROR "Use native-dns-transaction for Linux service acceptance")
endif()
add_executable(test_native_dns_desktop_lifecycle
    testNativeDnsDesktopLifecycle.cpp
    ../../service/server/nativednsservice.cpp)
target_include_directories(test_native_dns_desktop_lifecycle PRIVATE
    ../../client ../../service/server)
target_link_libraries(test_native_dns_desktop_lifecycle PRIVATE
    Qt6::Core Qt6::Network Qt6::Test)
if(TARGET amnezia::xray-bindings)
    # Production build: reuse exactly the service's existing Go runtime.
    target_link_libraries(test_native_dns_desktop_lifecycle PRIVATE amnezia::xray-bindings)
else()
    set(NATIVE_DNS_RUNTIME "" CACHE FILEPATH "Actual DNS-enabled Xray library/import library")
    set(NATIVE_DNS_INCLUDE "" CACHE PATH "Directory containing its generated amnezia_xray.h")
    if(NOT EXISTS "${NATIVE_DNS_RUNTIME}" OR NOT EXISTS "${NATIVE_DNS_INCLUDE}/amnezia_xray.h")
        message(FATAL_ERROR "A real DNS-enabled native Xray library and generated header are required; no stub")
    endif()
    target_include_directories(test_native_dns_desktop_lifecycle PRIVATE "${NATIVE_DNS_INCLUDE}")
    target_link_libraries(test_native_dns_desktop_lifecycle PRIVATE "${NATIVE_DNS_RUNTIME}")
endif()
if(WIN32)
    target_sources(test_native_dns_desktop_lifecycle PRIVATE
        ../../client/platforms/windows/daemon/windowsdnsrecovery.cpp
        ../../client/platforms/windows/daemon/windowsdnspolicy.cpp
        ../../client/platforms/windows/daemon/nativednsfirewall.cpp)
    target_link_libraries(test_native_dns_desktop_lifecycle PRIVATE
        iphlpapi advapi32 ws2_32 fwpuclnt rpcrt4 ole32 oleaut32 wbemuuid)
else()
    target_sources(test_native_dns_desktop_lifecycle PRIVATE
        ../../client/platforms/macos/daemon/macosdnsrecovery.cpp)
    target_link_libraries(test_native_dns_desktop_lifecycle PRIVATE
        "-framework SystemConfiguration" "-framework CoreFoundation"
        "-framework Security" resolv)
endif()
add_test(NAME NativeDnsDesktopLifecycle COMMAND test_native_dns_desktop_lifecycle)
set_tests_properties(NativeDnsDesktopLifecycle PROPERTIES TIMEOUT 60)
if(WIN32)
    set_property(TEST NativeDnsDesktopLifecycle APPEND PROPERTY ENVIRONMENT_MODIFICATION
        "PATH=path_list_prepend:$<TARGET_FILE_DIR:Qt6::Core>")
    foreach(directory IN LISTS CONAN_RUNTIME_LIB_DIRS amnezia-xray-bindings_BIN_DIRS_RELEASE amnezia-xray-bindings_BIN_DIRS_DEBUG)
        set_property(TEST NativeDnsDesktopLifecycle APPEND PROPERTY ENVIRONMENT_MODIFICATION
            "PATH=path_list_prepend:${directory}")
    endforeach()
    set(NATIVE_DNS_RUNTIME_DLL "" CACHE FILEPATH "Actual DNS-enabled Xray runtime DLL for standalone tests")
    if(NATIVE_DNS_RUNTIME_DLL)
        get_filename_component(runtime_directory "${NATIVE_DNS_RUNTIME_DLL}" DIRECTORY)
        set_property(TEST NativeDnsDesktopLifecycle APPEND PROPERTY ENVIRONMENT_MODIFICATION
            "PATH=path_list_prepend:${runtime_directory}")
    endif()
endif()
