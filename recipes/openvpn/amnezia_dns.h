/*
 * Amnezia native DNS hand-off. Included by the pinned OpenVPN init.c only.
 * The option is opt-in; ordinary management-up-down clients are unchanged.
 */
#ifndef AMNEZIA_NATIVE_DNS_H
#define AMNEZIA_NATIVE_DNS_H

#include "platform.h"
#include "dns.h"
#include <limits.h>

static unsigned long long amnezia_dns_serial;

static bool
amnezia_dns_confirm(const char *phase)
{
#ifdef ENABLE_MANAGEMENT
    if (!management)
    {
        return false;
    }
    if (amnezia_dns_serial == ULLONG_MAX)
    {
        return false;
    }
    /* Management matches NEED-OK types exactly. A late reply from a previous
     * publication/restore attempt must not confirm the next one. */
    char request[96];
    const int length = snprintf(request, sizeof(request), "%s:%llu", phase, ++amnezia_dns_serial);
    if (length < 0 || (size_t)length >= sizeof(request))
    {
        return false;
    }
    struct user_pass response;
    CLEAR(response);
    snprintf(response.username, sizeof(response.username),
             "Confirm service-owned native DNS transaction");
    const bool queried = management_query_user_pass(
        management, &response, request, GET_USER_PASS_NEED_OK, NULL);
    const bool confirmed = queried && streq(response.password, "ok");
    secure_memzero(&response, sizeof(response));
    return confirmed;
#else
    (void)phase;
    return false;
#endif
}

static void
amnezia_dns_restore_before_close(const struct options *options)
{
    if (!options->amnezia_external_dns)
    {
        return;
    }
    /* A failed/disconnected acknowledgement is NOT permission to tear down.
     * Keep the native interface/routes and service cleanup ownership available.
     * Forced process/OS termination is handled by the durable recovery journal,
     * not misrepresented as a confirmed graceful restore. */
    while (!amnezia_dns_confirm("AMNEZIA-DNS-RESTORE"))
    {
        msg(M_WARN, "Native DNS restore unconfirmed; retaining tunnel before teardown");
        platform_sleep_milliseconds(1000);
    }
}

static void
amnezia_dns_detach_native_servers(struct tuntap *tt)
{
#ifdef _WIN32
    /* Only the live driver copy changes. The original options remain complete
     * for the service, reconnects and native environment serialization. */
    tt->options.dns_len = 0;
    tt->options.dns6_len = 0;
    tt->options.domain = NULL;
    tt->options.domain_search_list_len = 0;
    tt->options.register_dns = false;
#else
    (void)tt;
#endif
}

static void
amnezia_dns_environment(const struct options *options, struct env_set *es)
{
    setenv_str(es, "amnezia_native_dns", "external");
    amnezia_setenv_dns_options(&options->dns_options, es);
#ifdef _WIN32
    /* Windows legacy DHCP options are not exported as foreign_option_N by
     * upstream. Serialize the unmodified original, never the detached copy. */
    struct gc_arena gc = gc_new();
    const struct tuntap_options *dns = &options->tuntap_options;
    char key[80];
    for (int i = 0; i < dns->dns_len; ++i)
    {
        snprintf(key, sizeof(key), "amnezia_legacy_dns4_%d", i + 1);
        setenv_str(es, key, print_in_addr_t(dns->dns[i], 0, &gc));
    }
    for (int i = 0; i < dns->dns6_len; ++i)
    {
        snprintf(key, sizeof(key), "amnezia_legacy_dns6_%d", i + 1);
        setenv_str(es, key, print_in6_addr(dns->dns6[i], 0, &gc));
    }
    setenv_str(es, "amnezia_legacy_domain", dns->domain);
    for (int i = 0; i < dns->domain_search_list_len; ++i)
    {
        snprintf(key, sizeof(key), "amnezia_legacy_search_%d", i + 1);
        setenv_str(es, key, dns->domain_search_list[i]);
    }
    gc_free(&gc);
#endif
}

static void
amnezia_dns_publish_preserved(const struct options *options, struct env_set *es,
                             const struct tuntap *tt)
{
    if (!options->amnezia_external_dns)
    {
        return;
    }
#ifdef ENABLE_MANAGEMENT
    if (!management)
    {
        msg(M_FATAL, "Native DNS hand-off requires the service management connection");
    }
    /* This is not a new add_routes result. The service may accept it only for
     * its already-owned, route-confirmed interface; never for a fresh owner. */
    if (!tt || !tt->actual_name || !tt->actual_name[0])
    {
        msg(M_FATAL, "Preserved native DNS hand-off requires the retained interface");
        return;
    }
    /* c2.es is recreated on soft restart, while the retained device is in c1.
     * Export its actual name, not the configured --dev or a previous frame. */
    setenv_str(es, "dev", tt->actual_name);
    setenv_str(es, "amnezia_native_routes", "preserved");
    amnezia_dns_environment(options, es);
    management_up_down(management, "UP", es);
    if (!amnezia_dns_confirm("AMNEZIA-DNS-PUBLISH"))
    {
        msg(M_FATAL, "Preserved native DNS publication was not confirmed");
    }
#else
    (void)es;
#endif
}

#endif
