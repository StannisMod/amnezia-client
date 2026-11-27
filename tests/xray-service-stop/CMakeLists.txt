cmake_minimum_required(VERSION 3.25)
project(XrayServiceStop LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
find_package(Qt6 REQUIRED COMPONENTS Core Network RemoteObjects DBus)
qt_standard_project_setup()
file(READ ../../client/core/protocols/xrayProtocol.cpp protocol)
string(FIND "${protocol}" "void XrayProtocol::stop()\n" begin)
string(FIND "${protocol}" "\nErrorCode XrayProtocol::startTun2Socks()" end)
math(EXPR length "${end} - ${begin}")
string(SUBSTRING "${protocol}" ${begin} ${length} stop)
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/production-stop.inc "${stop}")
qt_add_executable(xray_service_stop main.cpp
    ../../client/platforms/linux/daemon/linuxdnsrecovery.cpp)
qt6_add_repc_replicas(xray_service_stop ../../ipc/ipc_interface.rep ../../ipc/ipc_process_interface.rep)
target_include_directories(xray_service_stop PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    ../../ipc ../../client/mozilla/shared ../../client/core/protocols
    ../../client/platforms/linux/daemon)
target_link_libraries(xray_service_stop PRIVATE Qt6::Core Qt6::Network Qt6::RemoteObjects Qt6::DBus)
qt_add_executable(systemd_dns_probe systemdDnsProbe.cpp
    ../../client/platforms/linux/daemon/linuxdnsrecovery.cpp)
target_sources(systemd_dns_probe PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/moc_rep_ipc_interface_replica.cpp)
target_include_directories(systemd_dns_probe PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    ../../ipc ../../client/mozilla/shared ../../client/platforms/linux/daemon)
target_link_libraries(systemd_dns_probe PRIVATE Qt6::Core Qt6::Network Qt6::RemoteObjects Qt6::DBus)
