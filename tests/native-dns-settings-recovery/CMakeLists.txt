cmake_minimum_required(VERSION 3.25)
project(NativeDnsSettingsRecovery LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network Test)
enable_testing()
add_executable(test_dns_settings_recovery testDnsSettingsRecovery.cpp)
target_include_directories(test_dns_settings_recovery PRIVATE
    ../../client ../linux-dns-cache/stubs ../../client/mozilla/shared)
target_link_libraries(test_dns_settings_recovery PRIVATE Qt6::Core Qt6::Network Qt6::Test)
if(APPLE)
    target_sources(test_dns_settings_recovery PRIVATE
        ../../client/platforms/macos/daemon/macosdnsrecovery.cpp
        ../../client/platforms/macos/daemon/dnsutilsmacos.cpp
        ../../client/platforms/macos/daemon/dnsutilsmacos.h
        ../../client/daemon/dnsutils.h)
    target_link_libraries(test_dns_settings_recovery PRIVATE
        "-framework SystemConfiguration" "-framework CoreFoundation")
elseif(WIN32)
    target_sources(test_dns_settings_recovery PRIVATE
        ../../client/platforms/windows/daemon/nativednsfirewall.cpp
        ../../client/platforms/windows/daemon/windowsdnsrecovery.cpp
        ../../client/platforms/windows/daemon/windowsdnspolicy.cpp
        ../../client/platforms/windows/daemon/dnsutilswindows.cpp
        ../../client/platforms/windows/daemon/dnsutilswindows.h
        ../../client/daemon/dnsutils.h)
    target_link_libraries(test_dns_settings_recovery PRIVATE iphlpapi advapi32 ws2_32 fwpuclnt rpcrt4 ole32 oleaut32 wbemuuid)
endif()
add_test(NAME NativeDnsSettingsRecovery COMMAND test_dns_settings_recovery)
set_tests_properties(NativeDnsSettingsRecovery PROPERTIES TIMEOUT 30)
