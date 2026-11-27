#!/usr/bin/env python3
"""Compile the production native helper against instrumented native boundaries.

Linux/Windows preprocessor branches are exercised; this is not Windows runtime
acceptance. Sleeps/management replies are controlled so failure paths are bounded.
"""
from pathlib import Path
import subprocess
import tempfile


HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdlib.h>
#define ENABLE_MANAGEMENT 1
#define GET_USER_PASS_NEED_OK 4
#define M_WARN 1
#define M_FATAL 2
#define CLEAR(x) memset(&(x), 0, sizeof(x))
#define streq(a,b) (!strcmp((a),(b)))
struct user_pass { char username[256]; char password[256]; };
struct tuntap_options {
    unsigned int dns[4]; int dns_len;
    int dns6[4]; int dns6_len;
    const char *domain;
    const char *domain_search_list[10]; int domain_search_list_len;
    bool register_dns;
};
struct dns_options { const char *transport, *sni, *dnssec, *domain; };
struct options {
    bool amnezia_external_dns;
    struct dns_options dns_options;
    struct tuntap_options tuntap_options;
};
struct tuntap { struct tuntap_options options; const char *actual_name; };
struct env_set { char keys[32][80]; char values[32][256]; int count; };
static int manager;
static int *management = &manager;
static int attempts, sleeps, wipes, teardown;
static bool queried = true, forever;
static const char *answer = "ok", *expected_phase;
static unsigned long long last_serial;
static jmp_buf blocked_jump;
static const struct dns_options *expected_dns;
static bool management_query_user_pass(int *man, struct user_pass *up,
    const char *phase, unsigned int flags, const char *challenge)
{
    assert(man == &manager && flags == GET_USER_PASS_NEED_OK && challenge == NULL);
    assert(!strncmp(phase, expected_phase, strlen(expected_phase)));
    assert(phase[strlen(expected_phase)] == ':');
    char *end;
    const unsigned long long serial = strtoull(phase + strlen(expected_phase) + 1, &end, 10);
    assert(*end == 0 && serial > last_serial);
    last_serial = serial;
    assert(strstr(up->username, "service-owned"));
    assert(!teardown);
    ++attempts;
    if (forever && attempts == 4) longjmp(blocked_jump, 1);
    const char *reply = answer;
    if (!strncmp(phase, "AMNEZIA-DNS-RESTORE:", 20) && (forever || attempts < 3))
        reply = "cancel";
    strcpy(up->password, reply);
    return queried;
}
static void secure_memzero(void *data, size_t count)
{
    memset(data, 0, count); ++wipes;
    for (size_t i = 0; i < count; ++i) assert(((unsigned char *)data)[i] == 0);
}
static void msg(int level, const char *text)
{ assert(level == M_WARN && strstr(text, "retaining tunnel")); }
static void platform_sleep_milliseconds(unsigned int n)
{ assert(n == 1000 && !teardown); ++sleeps; }
static void setenv_str(struct env_set *es, const char *key, const char *value)
{
    if (!value) return;
    assert(es->count < 32);
    strcpy(es->keys[es->count], key);
    strcpy(es->values[es->count], value);
    ++es->count;
}
static const char *getenv_value(const struct env_set *es, const char *key)
{
    for (int i = 0; i < es->count; ++i)
        if (!strcmp(es->keys[i], key)) return es->values[i];
    return NULL;
}
static void amnezia_setenv_dns_options(const struct dns_options *dns, struct env_set *es)
{
    assert(dns == expected_dns);
    setenv_str(es, "dns_server_1_transport", dns->transport);
    setenv_str(es, "dns_server_1_sni", dns->sni);
    setenv_str(es, "dns_server_1_dnssec", dns->dnssec);
    setenv_str(es, "dns_server_1_resolve_domain_1", dns->domain);
}
static int publications;
static void management_up_down(int *man, const char *phase, struct env_set *es)
{
    assert(man == &manager && !strcmp(phase, "UP"));
    assert(!strcmp(getenv_value(es, "amnezia_native_routes"), "preserved"));
    assert(!strcmp(getenv_value(es, "amnezia_native_dns"), "external"));
    ++publications;
}
#ifdef _WIN32
struct gc_arena { int dummy; };
static struct gc_arena gc_new(void) { return (struct gc_arena){0}; }
static void gc_free(struct gc_arena *gc) { (void)gc; }
static const char *print_in_addr_t(unsigned int address, int flags, struct gc_arena *gc)
{ assert(address == 53 && flags == 0); (void)gc; return "192.0.2.53"; }
static const char *print_in6_addr(int address, int flags, struct gc_arena *gc)
{ assert(address == 6 && flags == 0); (void)gc; return "2001:db8::53"; }
#endif
#include "amnezia_dns.h"
int main(void)
{
    expected_phase = "AMNEZIA-DNS-PUBLISH";
    assert(amnezia_dns_confirm(expected_phase));
    assert(attempts == 1 && wipes == 1);
    queried = false;
    assert(!amnezia_dns_confirm(expected_phase)); /* A failed query returning 'ok' is not an ACK. */
    queried = true;
    answer = "cancel"; assert(!amnezia_dns_confirm(expected_phase));
    answer = "OK"; assert(!amnezia_dns_confirm(expected_phase));
    answer = ""; assert(!amnezia_dns_confirm(expected_phase));
    assert(attempts == 5 && wipes == 5);
    management = NULL; assert(!amnezia_dns_confirm(expected_phase));
    assert(attempts == 5 && wipes == 5);
    management = &manager; answer = "ok";

    struct options options = {0};
    attempts = sleeps = 0;
    amnezia_dns_restore_before_close(&options);
    assert(attempts == 0 && sleeps == 0); /* ON never waits or changes native DNS. */
    options.amnezia_external_dns = true;
    expected_phase = "AMNEZIA-DNS-RESTORE";
    amnezia_dns_restore_before_close(&options);
    ++teardown;
    assert(attempts == 3 && sleeps == 2 && teardown == 1);
    attempts = sleeps = teardown = 0; forever = true;
    if (!setjmp(blocked_jump)) {
        amnezia_dns_restore_before_close(&options);
        ++teardown;
        assert(!"Unconfirmed restoration authorized teardown");
    }
    assert(attempts == 4 && sleeps == 3 && teardown == 0);
    forever = false;

    options.dns_options = (struct dns_options){"DoT", "secure.example", "yes", "private.example"};
    expected_dns = &options.dns_options;
    options.tuntap_options = (struct tuntap_options){
        .dns = {53, 53}, .dns_len = 2, .dns6 = {6}, .dns6_len = 1,
        .domain = "private.example", .domain_search_list = {"one.example", "two.example"},
        .domain_search_list_len = 2, .register_dns = true
    };
    struct tuntap tt = {.options = options.tuntap_options};
    amnezia_dns_detach_native_servers(&tt);
#ifdef _WIN32
    assert(tt.options.dns_len == 0 && tt.options.dns6_len == 0);
    assert(tt.options.domain == NULL && tt.options.domain_search_list_len == 0);
    assert(!tt.options.register_dns);
#endif
    assert(options.tuntap_options.dns_len == 2 && options.tuntap_options.dns6_len == 1);
    assert(options.tuntap_options.domain_search_list_len == 2 && options.tuntap_options.register_dns);
    struct env_set es = {0};
    amnezia_dns_environment(&options, &es);
    assert(!strcmp(getenv_value(&es, "amnezia_native_dns"), "external"));
    assert(!strcmp(getenv_value(&es, "dns_server_1_sni"), "secure.example"));
    assert(!strcmp(getenv_value(&es, "dns_server_1_transport"), "DoT"));
    assert(!strcmp(getenv_value(&es, "dns_server_1_dnssec"), "yes"));
    assert(!strcmp(getenv_value(&es, "dns_server_1_resolve_domain_1"), "private.example"));
#ifdef _WIN32
    assert(!strcmp(getenv_value(&es, "amnezia_legacy_dns4_1"), "192.0.2.53"));
    assert(!strcmp(getenv_value(&es, "amnezia_legacy_dns4_2"), "192.0.2.53"));
    assert(!strcmp(getenv_value(&es, "amnezia_legacy_dns6_1"), "2001:db8::53"));
    assert(!strcmp(getenv_value(&es, "amnezia_legacy_domain"), "private.example"));
    assert(!strcmp(getenv_value(&es, "amnezia_legacy_search_1"), "one.example"));
    assert(!strcmp(getenv_value(&es, "amnezia_legacy_search_2"), "two.example"));
#endif
    es.count = 0;
    options.amnezia_external_dns = false;
    amnezia_dns_publish_preserved(&options, &es, NULL);
    assert(publications == 0 && es.count == 0);
    options.amnezia_external_dns = true;
    expected_phase = "AMNEZIA-DNS-PUBLISH";
    tt.actual_name = "retained-native0";
    amnezia_dns_publish_preserved(&options, &es, &tt);
    assert(publications == 1);
    assert(!strcmp(getenv_value(&es, "amnezia_native_routes"), "preserved"));
    assert(!strcmp(getenv_value(&es, "dev"), "retained-native0"));
    const int queries_before_exhaustion = attempts;
    amnezia_dns_serial = ULLONG_MAX;
    assert(!amnezia_dns_confirm("AMNEZIA-DNS-PUBLISH"));
    assert(attempts == queries_before_exhaustion);
    puts("PASS: production native helper: exact ACK, failed query, zeroization, retry/block before teardown, unchanged originals, full DNS metadata hand-off");
}
'''


def main():
    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="openvpn-dns-handoff-") as directory:
        path = Path(directory)
        (path / "test.c").write_text(HARNESS)
        (path / "platform.h").write_text("/* platform boundary is instrumented by the harness */\n")
        (path / "dns.h").write_text("/* native serializer is instrumented by the harness */\n")
        (path / "amnezia_dns.h").write_bytes((root / "recipes/openvpn/amnezia_dns.h").read_bytes())
        for name, flags in (("linux", []), ("windows-branch", ["-D_WIN32"])):
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", *flags,
                            str(path / "test.c"), "-o", str(path / name)], check=True)
            subprocess.run([str(path / name)], check=True)
            print(f"PASS: {name} isolated helper branch", flush=True)


if __name__ == "__main__":
    main()
