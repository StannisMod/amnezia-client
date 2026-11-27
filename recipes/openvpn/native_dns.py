"""Checked native DNS hand-off for the pinned desktop OpenVPN source."""

from pathlib import Path


ANCHOR = '''#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_up_down(management, "UP", es);
    }
#endif'''

REPLACEMENT = '''#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        /* Amnezia: UP is also sent when add_routes fails. Report the native
         * result explicitly; CONNECTED,SUCCESS omits route errors on macOS.
         * "unmanaged" must never authorize a service-owned DNS publication.
         * This does not alter native routes, scripts or their return values. */
        setenv_str(es, "amnezia_native_routes",
                   route_noexec_enabled(options, tt) ? "unmanaged"
                   : ret ? "success" : "failed");
        if (options->amnezia_external_dns)
        {
            amnezia_dns_environment(options, es);
        }
        management_up_down(management, "UP", es);
        if (options->amnezia_external_dns)
        {
            if (!ret || route_noexec_enabled(options, tt))
            {
                msg(M_FATAL, "Native DNS publication refused: native routes unconfirmed");
            }
            if (!amnezia_dns_confirm("AMNEZIA-DNS-PUBLISH"))
            {
                msg(M_FATAL, "Native DNS publication was not confirmed");
            }
        }
    }
#endif'''


def patch_source(text):
    if text.count(REPLACEMENT) == 1 and text.count(ANCHOR) == 0:
        return text
    if text.count(ANCHOR) != 1 or "amnezia_native_routes" in text:
        raise ValueError("Pinned OpenVPN route notification changed; refusing unchecked DNS overlay")
    return text.replace(ANCHOR, REPLACEMENT, 1)


def replace_checked(text, before, after):
    if text.count(after) == 1 and text.count(before) == after.count(before):
        return text
    if text.count(before) != 1:
        raise ValueError("Pinned OpenVPN DNS hand-off anchor changed; refusing unchecked overlay")
    return text.replace(before, after, 1)


def patch_files(files):
    result = dict(files)
    result["init.c"] = patch_source(result["init.c"])
    result["init.c"] = replace_checked(result["init.c"],
        '    if (tuntap_is_dco_win(c->c1.tuntap) && !is_tun_type_set(c->c1.tuntap))\n'
        '    {\n        do_close_tun_simple(c);\n        return;\n    }',
        '    if (tuntap_is_dco_win(c->c1.tuntap) && !is_tun_type_set(c->c1.tuntap))\n'
        '    {\n        amnezia_dns_restore_before_close(&c->options);\n'
        '        do_close_tun_simple(c);\n        return;\n    }')
    result["init.c"] = replace_checked(result["init.c"],
        '        add_wfp_block(c);\n    }\n    gc_free(&gc);\n    return ret;\n}',
        '        amnezia_dns_publish_preserved(&c->options, c->c2.es, c->c1.tuntap);\n'
        '        add_wfp_block(c);\n    }\n    gc_free(&gc);\n    return ret;\n}')
    result["init.c"] = replace_checked(result["init.c"],
        '#include "memdbg.h"\n',
        '#include "memdbg.h"\n#include "amnezia_dns.h"\n')
    # These anchors include following context so an already-applied overlay
    # cannot be mistaken for a still-unpatched nested substring.
    result["init.c"] = replace_checked(result["init.c"],
        '    init_tun_post(c->c1.tuntap, &c->c2.frame, &c->options.tuntap_options);\n\n    c->c1.tuntap_owned',
        '    init_tun_post(c->c1.tuntap, &c->c2.frame, &c->options.tuntap_options);\n'
        '    if (c->options.amnezia_external_dns)\n'
        '    {\n        amnezia_dns_detach_native_servers(c->c1.tuntap);\n    }\n\n    c->c1.tuntap_owned')
    result["init.c"] = replace_checked(result["init.c"],
        '    run_dns_up_down(false, &c->options, c->c1.tuntap, &c->persist.duri);\n',
        '    if (force || !(c->sig->signal_received == SIGUSR1 && c->options.persist_tun))\n'
        '    {\n        amnezia_dns_restore_before_close(&c->options);\n    }\n'
        '    run_dns_up_down(false, &c->options, c->c1.tuntap, &c->persist.duri);\n')
    result["options.h"] = replace_checked(result["options.h"],
        '    unsigned int management_flags;\n\n',
        '    unsigned int management_flags;\n'
        '    bool amnezia_external_dns; /* Service owns DNS publication and restore. */\n\n')
    result["options.c"] = replace_checked(result["options.c"],
        '    "--management-up-down : Report tunnel up/down events to management interface.\\n"\n',
        '    "--management-up-down : Report tunnel up/down events to management interface.\\n"\n'
        '    "--management-external-dns : Service-owned DNS publication and restore acknowledgement.\\n"\n')
    result["options.c"] = replace_checked(result["options.c"],
        '    else if (streq(p[0], "management-client") && !p[1])',
        '    else if (streq(p[0], "management-external-dns") && !p[1])\n'
        '    {\n        VERIFY_PERMISSION(OPT_P_GENERAL);\n'
        '        options->amnezia_external_dns = true;\n'
        '        options->management_flags |= MF_UP_DOWN;\n    }\n'
        '    else if (streq(p[0], "management-client") && !p[1])')
    verification = '''    if (o->amnezia_external_dns)
    {
        if (o->up_script || o->down_script || o->route_script || o->route_predown_script
            || dns_updown_user_set(&o->dns_options))
        {
            msg(M_USAGE, "--management-external-dns cannot share DNS ownership with caller scripts");
        }
#ifdef ENABLE_MANAGEMENT
        if (!o->management_addr || !streq(o->management_addr, "127.0.0.1")
            || !(o->management_flags & MF_CONNECT_AS_CLIENT))
        {
            msg(M_USAGE, "--management-external-dns requires a local IPv4 management client");
        }
#else
        msg(M_USAGE, "--management-external-dns requires management support");
#endif
#ifdef TARGET_ANDROID
        msg(M_USAGE, "--management-external-dns is a desktop service protocol");
#endif
    }

'''
    result["options.c"] = replace_checked(result["options.c"],
        'options_postprocess_verify(const struct options *o)\n{\n    if (o->connection_list)',
        'options_postprocess_verify(const struct options *o)\n{\n' + verification +
        '    if (o->connection_list)')
    result["dns.c"] = replace_checked(result["dns.c"],
        '    if (!o->dns_options.servers)\n',
        '    if (o->amnezia_external_dns || !o->dns_options.servers)\n')
    result["dns.c"] = replace_checked(result["dns.c"],
        'static void\nupdown_env_set(bool up, const struct dns_options *o, const struct tuntap *tt, struct env_set *es)',
        'void\namnezia_setenv_dns_options(const struct dns_options *o, struct env_set *es)\n'
        '''{
    /* A native restart/update may select fewer servers or remove TLS metadata.
     * Serialize a complete selection, not a merge with stale environment keys. */
    struct gc_arena gc = gc_new();
    struct env_item *item = es->list;
    while (item)
    {
        struct env_item *next = item->next;
        if (!strncmp(item->string, "dns_server_", 11)
            || !strncmp(item->string, "dns_search_domain_", 18)
            || !strncmp(item->string, "amnezia_dns_priority_", 21)
            || !strncmp(item->string, "amnezia_legacy_", 15))
        {
            char *key = string_alloc(item->string, &gc);
            char *equals = strchr(key, '=');
            if (equals)
            {
                *equals = 0;
                setenv_del(es, key);
            }
        }
        item = next;
    }
    setenv_dns_options(o, es);
    int index = 1;
    for (const struct dns_server *server = o->servers; server; server = server->next, ++index)
    {
        char key[80];
        snprintf(key, sizeof(key), "amnezia_dns_priority_%d", index);
        setenv_long_long(es, key, server->priority);
    }
    gc_free(&gc);
}

'''
        'static void\nupdown_env_set(bool up, const struct dns_options *o, const struct tuntap *tt, struct env_set *es)')
    result["dns.h"] = replace_checked(result["dns.h"],
        'void show_dns_options(const struct dns_options *o);\n',
        'void show_dns_options(const struct dns_options *o);\n\n'
        '/* Preserve the native serializer for the service-owned DNS hand-off. */\n'
        'void amnezia_setenv_dns_options(const struct dns_options *o, struct env_set *es);\n')
    # Teardown retains the original SIGTERM/SIGHUP in siginfo_static. Ordinary
    # credential queries must still honor it, but the restore barrier must be
    # able to receive its ACK without clearing or replacing that native signal.
    query_start = result["manage.c"].index("management_query_user_pass(struct management *man,")
    query_end = result["manage.c"].index("\nstatic int\nmanagement_query_multiline", query_start)
    query = result["manage.c"][query_start:query_end]
    query = replace_checked(query,
        "        volatile int signal_received = 0;\n",
        "        volatile int signal_received = 0;\n"
        '        const bool amnezia_restore = (flags & GET_USER_PASS_NEED_OK)\n'
        '            && !strncmp(type, "AMNEZIA-DNS-RESTORE:", 20);\n'
        "        volatile int *query_signal = amnezia_restore ? NULL : &signal_received;\n")
    for before, after in (
        ("man_wait_for_client_connection(man, &signal_received, 0, MWCC_PASSWORD_WAIT);",
         "man_wait_for_client_connection(man, query_signal, 0, MWCC_PASSWORD_WAIT);"),
        ("man_standalone_event_loop(man, &signal_received, 0);",
         "man_standalone_event_loop(man, query_signal, 0);"),
        ("man_check_for_signals(&signal_received);", "man_check_for_signals(query_signal);"),
    ):
        query = replace_checked(query, before, after)
    result["manage.c"] = result["manage.c"][:query_start] + query + result["manage.c"][query_end:]
    return result


def apply(source_folder, overlay_folder=None):
    directory = Path(source_folder) / "src/openvpn"
    # Validate the complete set before the first write; a source mismatch must
    # not leave a half-applied suppression/restore protocol.
    files = {name: (directory / name).read_text()
             for name in ("init.c", "options.h", "options.c", "dns.c", "dns.h", "manage.c")}
    updated = patch_files(files)
    helper = Path(overlay_folder or Path(__file__).parent) / "amnezia_dns.h"
    helper_data = helper.read_bytes()
    for name, text in updated.items():
        if text != files[name]:
            (directory / name).write_text(text)
    (directory / helper.name).write_bytes(helper_data)
