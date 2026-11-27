# Qt Network's Kerberos dependencies are not present on every supported desktop.
# Ship this dependency chain while leaving glibc and the graphics stack to the OS.
find_program(AMNEZIA_PATCHELF patchelf REQUIRED)
install(CODE "
    file(GET_RUNTIME_DEPENDENCIES
        LIBRARIES \"$<TARGET_FILE:Qt6::Network>\"
        RESOLVED_DEPENDENCIES_VAR _network_dependencies)
    foreach(_dependency IN LISTS _network_dependencies)
        get_filename_component(_name \"\${_dependency}\" NAME)
        if(_name MATCHES \"^lib(gssapi_krb5|krb5|k5crypto|krb5support|com_err|keyutils)\\\\.so\\\\.\")
            file(INSTALL
                DESTINATION \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}\"
                TYPE SHARED_LIBRARY FOLLOW_SYMLINK_CHAIN
                FILES \"\${_dependency}\")
            execute_process(COMMAND \"${AMNEZIA_PATCHELF}\" --set-rpath \"$ORIGIN\"
                \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/\${_name}\"
                COMMAND_ERROR_IS_FATAL ANY)
        endif()
    endforeach()
" COMPONENT AmneziaVPN)

foreach(_package libkrb5-3 libcom-err2 libkeyutils1)
    install(FILES "/usr/share/doc/${_package}/copyright"
        DESTINATION "${CMAKE_INSTALL_BINDIR}/linux-network-licenses"
        RENAME "${_package}.copyright" COMPONENT AmneziaVPN)
endforeach()
