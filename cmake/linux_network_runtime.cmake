# Qt Network's Kerberos dependencies are not present on every supported desktop.
# Ship this dependency chain while leaving glibc and the graphics stack to the OS.
install(CODE "
    file(GET_RUNTIME_DEPENDENCIES
        LIBRARIES \"$<TARGET_FILE:Qt6::Network>\"
        RESOLVED_DEPENDENCIES_VAR _network_dependencies)
    foreach(_dependency IN LISTS _network_dependencies)
        get_filename_component(_name \"\${_dependency}\" NAME)
        if(_name MATCHES \"^lib(gssapi_krb5|krb5|k5crypto|krb5support|com_err|keyutils)\\\\.so\\\\.\")
            file(INSTALL
                DESTINATION \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}\"
                TYPE SHARED_LIBRARY FOLLOW_SYMLINK_CHAIN
                FILES \"\${_dependency}\")
        endif()
    endforeach()
" COMPONENT AmneziaVPN)
