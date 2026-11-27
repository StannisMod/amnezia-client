set(CPACK_PACKAGE_VENDOR            AmneziaVPN)
set(CPACK_PACKAGE_VERSION           ${AMNEZIAVPN_VERSION})
if(WIN32)
    set(CPACK_PACKAGE_FILE_NAME "AmneziaVPN_${AMNEZIAVPN_VERSION}_windows_x64")
elseif(APPLE AND NOT IOS AND NOT MACOS_NE)
    set(CPACK_PACKAGE_FILE_NAME "AmneziaVPN_${AMNEZIAVPN_VERSION}_macos_x64")
elseif(LINUX AND NOT ANDROID)
    set(CPACK_PACKAGE_FILE_NAME "AmneziaVPN_${AMNEZIAVPN_VERSION}_linux_x64")
endif()
set(CPACK_PACKAGE_INSTALL_DIRECTORY AmneziaVPN)
set(CPACK_PACKAGE_EXECUTABLES       AmneziaVPN AmneziaVPN)
set(CPACK_PRE_BUILD_SCRIPTS         ${CMAKE_CURRENT_LIST_DIR}/sign_binaries.cmake)
set(CPACK_POST_BUILD_SCRIPTS        ${CMAKE_CURRENT_LIST_DIR}/sign_packages.cmake)
set(CPACK_PROJECT_CONFIG_FILE       ${CMAKE_CURRENT_LIST_DIR}/CPackOptions.cmake)
set(CPACK_RESOURCE_FILE_LICENSE     ${CMAKE_SOURCE_DIR}/deploy/data/LICENSE.txt)

list(PREPEND CPACK_COMPONENTS_ALL AmneziaVPN)

if(APPLE)
    set(CPACK_GENERATOR productbuild)
else()
    set(CPACK_GENERATOR IFW)
endif()

# === CPack IFW generator settings ===
set(CPACK_IFW_PACKAGE_NAME                          AmneziaVPN)
set(CPACK_IFW_PACKAGE_TITLE                         AmneziaVPN)
set(CPACK_IFW_PACKAGE_WIZARD_DEFAULT_WIDTH          600)
set(CPACK_IFW_PACKAGE_WIZARD_DEFAULT_HEIGHT         380)
set(CPACK_IFW_PACKAGE_WIZARD_STYLE                  Modern)
set(CPACK_IFW_PACKAGE_REMOVE_TARGET_DIR             ON)
set(CPACK_IFW_PACKAGE_ALLOW_SPACE_IN_PATH           ON)
set(CPACK_IFW_PACKAGE_ALLOW_NON_ASCII_CHARACTERS    ON)
set(CPACK_IFW_PACKAGE_CONTROL_SCRIPT                ${CMAKE_SOURCE_DIR}/deploy/installer/qif/controlscript.js)

# === CPack WIX generator settings ===
set(CPACK_WIX_VERSION               4)
set(CPACK_WIX_UPGRADE_GUID          "{2D55AC62-96D6-4692-8C05-0D85BBF95485}")
set(CPACK_WIX_PRODUCT_ICON          ${CMAKE_SOURCE_DIR}/client/images/app.ico)
set(CPACK_WIX_CUSTOM_XMLNS          "util=http://wixtoolset.org/schemas/v4/wxs/util")
# PowerShell's documented UTF-16LE EncodedCommand avoids XML whitespace
# normalization, MSI property expansion and command-line quoting differences.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/deploy/data/windows/stop_native_services.ps1")
execute_process(COMMAND "${Python3_EXECUTABLE}" -c
    "import base64,pathlib,sys; print(base64.b64encode(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8').encode('utf-16le')).decode('ascii'))"
    "${CMAKE_SOURCE_DIR}/deploy/data/windows/stop_native_services.ps1"
    OUTPUT_VARIABLE AMNEZIA_WINDOWS_STOP_ENCODED OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)
set(_AMNEZIA_WIX_PATCH_SERVICE "${CMAKE_CURRENT_BINARY_DIR}/native-service-install-patch.xml")
configure_file("${CMAKE_SOURCE_DIR}/deploy/installer/wix/service_install_patch.xml"
    "${_AMNEZIA_WIX_PATCH_SERVICE}" @ONLY)
set(_AMNEZIA_IFW_COMPONENT_SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/native-componentscript.js")
file(READ "${CMAKE_SOURCE_DIR}/deploy/installer/qif/componentscript.js" _AMNEZIA_IFW_SCRIPT)
# Preserve IFW's own @TargetDir@ substitutions.
string(REPLACE "@AMNEZIA_WINDOWS_STOP_ENCODED@" "${AMNEZIA_WINDOWS_STOP_ENCODED}"
    _AMNEZIA_IFW_SCRIPT "${_AMNEZIA_IFW_SCRIPT}")
file(WRITE "${_AMNEZIA_IFW_COMPONENT_SCRIPT}" "${_AMNEZIA_IFW_SCRIPT}")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/deploy/installer/qif/componentscript.js")
set(_AMNEZIA_WIX_PATCH_CLOSE_APP "${CMAKE_CURRENT_BINARY_DIR}/native-close-client-patch.xml")
configure_file("${CMAKE_SOURCE_DIR}/deploy/installer/wix/close_client_patch.xml"
    "${_AMNEZIA_WIX_PATCH_CLOSE_APP}" @ONLY)
file(TO_CMAKE_PATH                  "${_AMNEZIA_WIX_PATCH_SERVICE}" _AMNEZIA_WIX_PATCH_SERVICE_CMAKE)
file(TO_CMAKE_PATH                  "${_AMNEZIA_WIX_PATCH_CLOSE_APP}" _AMNEZIA_WIX_PATCH_CLOSE_APP_CMAKE)
list(APPEND CPACK_WIX_PATCH_FILE    "${_AMNEZIA_WIX_PATCH_SERVICE_CMAKE}" "${_AMNEZIA_WIX_PATCH_CLOSE_APP_CMAKE}")
list(APPEND CPACK_WIX_EXTENSIONS    "WixToolset.Util.wixext")

# === CPack productbuild generator settings ===
set(CPACK_PRODUCTBUILD_IDENTIFIER       org.amneziavpn)
set(CPACK_PREFLIGHT_AMNEZIAVPN_SCRIPT   ${CMAKE_SOURCE_DIR}/deploy/data/macos/post_uninstall.sh)
set(CPACK_POSTFLIGHT_AMNEZIAVPN_SCRIPT  ${CMAKE_SOURCE_DIR}/deploy/data/macos/post_install.sh)
set(CPACK_POSTFLIGHT_UNINSTALL_SCRIPT   ${CMAKE_SOURCE_DIR}/deploy/data/macos/post_uninstall.sh)
# provide custom CPack.distribution.dist.in
list(APPEND CMAKE_MODULE_PATH           ${CMAKE_SOURCE_DIR}/deploy/data/macos)

if(LINUX AND NOT ANDROID)
    install(FILES
        ${CMAKE_SOURCE_DIR}/deploy/data/linux/AmneziaVPN.service
        ${CMAKE_SOURCE_DIR}/deploy/data/linux/AmneziaVPN.png
        ${CMAKE_SOURCE_DIR}/deploy/data/linux/AmneziaVPN.desktop
        ${CMAKE_SOURCE_DIR}/deploy/data/linux/post_install.sh
        ${CMAKE_SOURCE_DIR}/deploy/data/linux/post_uninstall.sh
        DESTINATION "."
        COMPONENT AmneziaVPN
    )
endif()

if(WIN32)
    configure_file("${CMAKE_SOURCE_DIR}/deploy/data/windows/post_install.cmd"
        "${CMAKE_CURRENT_BINARY_DIR}/post_install.cmd" @ONLY)
    configure_file("${CMAKE_SOURCE_DIR}/deploy/data/windows/post_uninstall.cmd"
        "${CMAKE_CURRENT_BINARY_DIR}/post_uninstall.cmd" @ONLY)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/post_install.cmd
        ${CMAKE_CURRENT_BINARY_DIR}/post_uninstall.cmd
        DESTINATION "."
        COMPONENT AmneziaVPN
    )

    set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_SKIP TRUE)
    include(InstallRequiredSystemLibraries)
    if(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS)
        install(PROGRAMS ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS}
            DESTINATION "."
            COMPONENT AmneziaVPN
        )
    else()
        message(WARNING "MSVC runtime libraries were not found, packages will not ship them")
    endif()
endif()

if (APPLE AND NOT IOS AND NOT MACOS_NE)
    install(FILES ${CMAKE_SOURCE_DIR}/deploy/data/macos/AmneziaVPN.plist
        DESTINATION "AmneziaVPN.app/Contents/Resources"
        COMPONENT AmneziaVPN
    )
endif()

include(CPackIFW)
cpack_ifw_configure_component(AmneziaVPN
    VERSION ${AMNEZIAVPN_VERSION}
    RELEASE_DATE ${RELEASE_DATE}
    REQUIRES_ADMIN_RIGHTS
    FORCED_INSTALLATION
    SCRIPT ${_AMNEZIA_IFW_COMPONENT_SCRIPT}
)

include(CPack)
cpack_add_component(Uninstall
    DISPLAY_NAME "Uninstall AmneziaVPN"
    REQUIRES_ADMIN_RIGHTS
    DISABLED
)
