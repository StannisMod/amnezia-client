find_program(GO_EXEC go REQUIRED)
set(_dns_cloak "${AMNEZIA_DNS_CLOAK_SOURCE}")
if(NOT IS_DIRECTORY "${_dns_cloak}")
    message(FATAL_ERROR "Prepared original Cloak + native DNS source is missing")
endif()
set(_go_arch "")
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(_go_arch arm64)
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(_go_arch arm)
elseif(ANDROID_ABI STREQUAL "x86")
    set(_go_arch 386)
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(_go_arch amd64)
else()
    message(FATAL_ERROR "Unsupported native Cloak ABI: ${ANDROID_ABI}")
endif()
file(GLOB_RECURSE _dns_go_inputs CONFIGURE_DEPENDS "${_dns_cloak}/*.go")
file(GLOB_RECURSE _dns_routing_inputs CONFIGURE_DEPENDS
    "${_dns_cloak}/amnezia-routing/dnsguard/*.go"
    "${_dns_cloak}/amnezia-routing/nativedns/*.go"
    "${_dns_cloak}/amnezia-routing/internal/builddeps/*.go")
set(_dns_library "${CMAKE_CURRENT_BINARY_DIR}/libck-ovpn-plugin.so")
add_custom_command(
    OUTPUT "${_dns_library}" "${CMAKE_CURRENT_BINARY_DIR}/libck-ovpn-plugin.h"
    COMMAND "${CMAKE_COMMAND}" -E env
        CGO_ENABLED=1 GOOS=android "GOARCH=${_go_arch}" GOARM=7
        "CC=${CMAKE_C_COMPILER} --target=${CMAKE_C_COMPILER_TARGET} --sysroot=${CMAKE_SYSROOT}"
        GOTOOLCHAIN=local
        "${GO_EXEC}" build -mod=readonly -tags=amnezia_openvpn_dns
        -trimpath "-ldflags=-w -s -buildid= -checklinkname=0"
        -buildmode=c-shared -o "${_dns_library}" ./cmd/ck-ovpn-plugin
    WORKING_DIRECTORY "${_dns_cloak}"
    DEPENDS ${_dns_go_inputs} ${_dns_routing_inputs}
        "${_dns_cloak}/go.mod" "${_dns_cloak}/go.sum"
    VERBATIM)
add_custom_target(ck_ovpn_plugin_go DEPENDS "${_dns_library}")
add_library(libck-ovpn-plugin SHARED IMPORTED GLOBAL)
add_dependencies(libck-ovpn-plugin ck_ovpn_plugin_go)
set_target_properties(libck-ovpn-plugin PROPERTIES
    IMPORTED_LOCATION "${_dns_library}"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_BINARY_DIR}")
