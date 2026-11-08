find_package(Qt6 REQUIRED COMPONENTS Qml RemoteObjects)
get_filename_component(REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
qt_add_executable(routing-wireguard-probe main.cpp
    "${REPO_ROOT}/client/core/protocols/wireGuardProtocol.cpp" "${REPO_ROOT}/client/core/protocols/wireGuardProtocol.h"
    "${REPO_ROOT}/client/core/protocols/vpnProtocol.cpp" "${REPO_ROOT}/client/core/protocols/vpnProtocol.h"
    "${REPO_ROOT}/client/core/utils/errorStrings.cpp" "${REPO_ROOT}/client/core/utils/errorCodes.h"
    "${REPO_ROOT}/client/mozilla/localsocketcontroller.cpp" "${REPO_ROOT}/client/mozilla/localsocketcontroller.h"
    "${REPO_ROOT}/client/mozilla/controllerimpl.h")
qt_add_repc_replicas(routing-wireguard-probe "${REPO_ROOT}/ipc/ipc_interface.rep" "${REPO_ROOT}/ipc/ipc_process_interface.rep")
target_include_directories(routing-wireguard-probe PRIVATE
    "${REPO_ROOT}/tests/linux-dns-cache/stubs" "${REPO_ROOT}/client" "${REPO_ROOT}/client/mozilla/shared"
    "${REPO_ROOT}" "${REPO_ROOT}/ipc" "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_definitions(routing-wireguard-probe PRIVATE MZ_LINUX)
target_link_libraries(routing-wireguard-probe PRIVATE Qt6::Core Qt6::Network Qt6::RemoteObjects Qt6::Qml)
target_compile_options(routing-wireguard-probe PRIVATE -ffunction-sections -fdata-sections)
target_link_options(routing-wireguard-probe PRIVATE -Wl,--gc-sections)
set_target_properties(routing-wireguard-probe PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/..")
