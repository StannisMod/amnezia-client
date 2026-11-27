#!/usr/bin/env python3
"""Exercise the actual pinned do_route function with instrumented OS boundaries.

No VPN/runtime acceptance is inferred from this isolated native-function test.
Pass an existing complete OpenVPN source tree; no fetching is performed.
"""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("overlay", root / "recipes/openvpn/native_dns.py")
    overlay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(overlay)
    original = (args.source / "src/openvpn/init.c").read_text()
    originals = {name: (args.source / "src/openvpn" / name).read_text()
                 for name in ("init.c", "options.h", "options.c", "dns.c", "dns.h", "manage.c")}
    patched = overlay.patch_files(originals)
    updated = patched["init.c"]
    # Conan may expose the pristine source or the already-overlaid build source.
    route_original = original.replace(overlay.REPLACEMENT, overlay.ANCHOR)
    assert updated != route_original
    assert overlay.patch_files(patched) == patched
    for malformed in (route_original.replace(overlay.ANCHOR, ""), route_original + overlay.ANCHOR,
                      route_original + '\n/* amnezia_native_routes */'):
        try:
            overlay.patch_source(malformed)
        except ValueError:
            pass
        else:
            raise AssertionError("Changed/ambiguous pinned source accepted")

    start = updated.index("bool\ndo_route(")
    end = updated.index("\n}\n", start) + 3
    function = updated[start:end]
    harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
#define ENABLE_MANAGEMENT 1
#define OPENVPN_PLUGIN_ROUTE_UP 1
#define OPENVPN_PLUGIN_FUNC_SUCCESS 0
#define M_WARN 0
#define M_FATAL 1
#define ROUTE_OPTION_FLAGS(o) 0
typedef int openvpn_net_ctx_t;
struct options { bool route_noexec; const char *route_script; bool amnezia_external_dns; };
struct route_list { int unused; };
struct route_ipv6_list { int unused; };
struct tuntap { int unused; };
struct plugin_list { int unused; };
struct env_set { const char *status; };
struct argv { int unused; };
static int manager;
static int *management = &manager;
static bool route_result;
static int native_calls, notifications;
static const char *expected;
static int environment_calls, confirmation_calls;
static bool confirmation = true, expect_fatal;
static jmp_buf fatal_jump;
static void amnezia_dns_environment(const struct options *o, struct env_set *es)
{ (void)o; (void)es; ++environment_calls; }
static bool amnezia_dns_confirm(const char *phase)
{ assert(!strcmp(phase, "AMNEZIA-DNS-PUBLISH")); ++confirmation_calls; return confirmation; }
static bool route_noexec_enabled(const struct options *o, const struct tuntap *tt)
{ (void)tt; return o->route_noexec; }
static bool add_routes(struct route_list *a, struct route_ipv6_list *b,
    const struct tuntap *tt, int flags, struct env_set *es, openvpn_net_ctx_t *ctx)
{ (void)a; (void)b; (void)tt; (void)flags; (void)es; (void)ctx; ++native_calls; return route_result; }
static int route_did_redirect_default_gateway(struct route_list *r) { (void)r; return 0; }
static void setenv_int(struct env_set *es, const char *key, int value)
{ (void)es; (void)key; (void)value; }
static void setenv_str(struct env_set *es, const char *key, const char *value)
{ if (!strcmp(key, "amnezia_native_routes")) es->status = value; }
static void management_up_down(int *man, const char *phase, struct env_set *es)
{ (void)man; assert(!strcmp(phase, "UP")); assert(es->status); assert(!strcmp(es->status, expected)); ++notifications; }
static bool plugin_defined(const struct plugin_list *p, int type) { (void)p; (void)type; return false; }
static int plugin_call(const struct plugin_list *p, int type, void *a, void *b, struct env_set *es)
{ (void)p; (void)type; (void)a; (void)b; (void)es; return 0; }
static void msg(int level, const char *text)
{ (void)text; if (level == M_FATAL) { assert(expect_fatal); longjmp(fatal_jump, 1); } }
static struct argv argv_new(void) { return (struct argv){0}; }
static void argv_parse_cmd(struct argv *a, const char *s) { (void)a; (void)s; }
static void openvpn_run_script(struct argv *a, struct env_set *es, int f, const char *s)
{ (void)a; (void)es; (void)f; (void)s; }
static void argv_free(struct argv *a) { (void)a; }
'''
    checks = r'''
int main(void)
{
    struct options options = {0};
    struct route_list routes = {0};
    struct env_set env = {0};
    route_result = true; expected = "success";
    assert(do_route(&options, &routes, NULL, NULL, NULL, &env, NULL));
    assert(native_calls == 1 && notifications == 1);
    route_result = false; expected = "failed";
    assert(!do_route(&options, &routes, NULL, NULL, NULL, &env, NULL));
    assert(native_calls == 2 && notifications == 2);
    options.route_noexec = true; expected = "unmanaged";
    assert(do_route(&options, &routes, NULL, NULL, NULL, &env, NULL));
    assert(native_calls == 2 && notifications == 3);
    options.route_noexec = false; expected = "success";
    assert(do_route(&options, NULL, NULL, NULL, NULL, &env, NULL));
    assert(native_calls == 2 && notifications == 4);
    management = NULL;
    route_result = false;
    assert(!do_route(&options, &routes, NULL, NULL, NULL, &env, NULL));
    assert(native_calls == 3 && notifications == 4);
    assert(environment_calls == 0 && confirmation_calls == 0);
    management = &manager;
    options.amnezia_external_dns = true;
    route_result = true; expected = "success";
    assert(do_route(&options, &routes, NULL, NULL, NULL, &env, NULL));
    assert(environment_calls == 1 && confirmation_calls == 1);
    expect_fatal = true;
    confirmation = false;
    if (!setjmp(fatal_jump)) {
        do_route(&options, &routes, NULL, NULL, NULL, &env, NULL);
        assert(!"Unconfirmed publication continued");
    }
    assert(environment_calls == 2 && confirmation_calls == 2);
    route_result = false; expected = "failed";
    if (!setjmp(fatal_jump)) {
        do_route(&options, &routes, NULL, NULL, NULL, &env, NULL);
        assert(!"Failed routes authorized publication");
    }
    assert(environment_calls == 3 && confirmation_calls == 2);
    options.route_noexec = true; expected = "unmanaged";
    if (!setjmp(fatal_jump)) {
        do_route(&options, &routes, NULL, NULL, NULL, &env, NULL);
        assert(!"Unmanaged routes authorized publication");
    }
    assert(environment_calls == 4 && confirmation_calls == 2);
}
'''
    with tempfile.TemporaryDirectory(prefix="openvpn-dns-overlay-") as directory:
        path = Path(directory)
        (path / "test.c").write_text(harness + function + checks)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(path / "test.c"), "-o", str(path / "test")], check=True)
        subprocess.run([str(path / "test")], check=True)
        dns_start = patched["dns.c"].index("void\nrun_dns_up_down(")
        dns_end = patched["dns.c"].index("\n}\n", dns_start) + 3
        dns_function = patched["dns.c"][dns_start:dns_end]
        dns_harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#define M_WARN 1
#define IPW32_SET_DHCP_MASQ 3
#define IPW32_SET_ADAPTIVE 4
struct dns_server {
    struct dns_server *next; long priority;
    size_t addr_count; struct { int family; } addr[2];
};
struct dns_options { struct dns_server *servers; };
struct tuntap_options { int ip_win32_type; };
struct options {
    bool amnezia_external_dns;
    struct dns_options dns_options;
    struct tuntap_options tuntap_options;
};
struct tuntap { bool did_ifconfig_setup, did_ifconfig_ipv6_setup; };
struct dns_updown_runner_info { int unused; };
static int publications;
static struct dns_server *original_server;
static void msg(int level, const char *format, ...) { (void)level; (void)format; }
#ifdef _WIN32
static void run_up_down_service(bool up, struct options *o, const struct tuntap *tt)
{ (void)up; (void)tt; assert(o->dns_options.servers == original_server); ++publications; }
#else
static void run_up_down_command(bool up, struct options *o, const struct tuntap *tt,
    struct dns_updown_runner_info *duri)
{ (void)up; (void)tt; (void)duri; assert(o->dns_options.servers == original_server); ++publications; }
#endif
'''
        dns_checks = r'''
int main(void)
{
    struct dns_server server = {.priority = -3, .addr_count = 2,
        .addr = {{AF_INET}, {AF_INET6}}};
    original_server = &server;
    struct options options = {.amnezia_external_dns = true, .dns_options = {&server}};
    struct tuntap tt = {true, true};
    run_dns_up_down(true, &options, &tt, NULL);
    run_dns_up_down(false, &options, &tt, NULL);
    assert(publications == 0 && options.dns_options.servers == &server);
    assert(server.priority == -3 && server.addr_count == 2);
    assert(server.addr[0].family == AF_INET && server.addr[1].family == AF_INET6);
    options.amnezia_external_dns = false;
    run_dns_up_down(true, &options, &tt, NULL);
    run_dns_up_down(false, &options, &tt, NULL);
    assert(publications == 2);
#ifdef _WIN32
    options.tuntap_options.ip_win32_type = IPW32_SET_DHCP_MASQ;
    run_dns_up_down(true, &options, &tt, NULL);
    assert(publications == 2); /* Native ON DHCP behavior remains intact. */
#endif
    options.dns_options.servers = NULL;
    run_dns_up_down(true, &options, &tt, NULL);
    assert(publications == 2);
}
'''
        (path / "dns.c").write_text(dns_harness + dns_function + dns_checks)
        for name, flags in (("dns-linux", []), ("dns-windows-branch", ["-D_WIN32"])):
            # Upstream leaves duri unused in its Windows branch. Match the
            # existing production -Wno-unused-parameter flag, not a source edit.
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-parameter", *flags,
                            str(path / "dns.c"), "-o", str(path / name)], check=True)
            subprocess.run([str(path / name)], check=True)
            print(f"PASS: actual run_dns_up_down {name}: native OFF publication suppressed, originals/ON retained", flush=True)
        close_start = updated.index("static void\ndo_close_tun(struct context *c, bool force)")
        close_end = updated.index("\n}\n", close_start) + 3
        close_function = updated[close_start:close_end]
        close_harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <signal.h>
#include <setjmp.h>
typedef unsigned int in_addr_t;
#define ROUTE_OPTION_FLAGS(o) 0
#define IA_EMPTY_IF_UNDEF 0
#define OPENVPN_PLUGIN_ROUTE_PREDOWN 1
#define OPENVPN_PLUGIN_DOWN 2
struct gc_arena { int unused; };
struct tuntap { const char *actual_name; in_addr_t local, remote_netmask; unsigned long adapter_index; };
struct options {
    bool persist_tun, down_pre, up_restart, amnezia_external_dns;
    const char *route_predown_script, *down_script;
};
struct signal_info { int signal_received; const char *signal_text; };
struct context {
    struct options options;
    struct {
        struct tuntap *tuntap; bool tuntap_owned;
        void *route_list, *route_ipv6_list;
    } c1;
    struct { void *es; struct { int tun_mtu; } frame; } c2;
    struct { int duri; } persist;
    struct { int unused; } net_ctx;
    struct signal_info *sig;
    void *plugins;
};
static struct context *static_context;
static int restores, dns_down, removed_routes, closed, scripts;
static bool blocked, confirmed, external;
static bool dco_win, typed = true;
static jmp_buf blocked_close;
static bool tuntap_is_dco_win(const struct tuntap *tt) { (void)tt; return dco_win; }
static bool is_tun_type_set(const struct tuntap *tt) { return tt != NULL && typed; }
static struct gc_arena gc_new(void) { return (struct gc_arena){0}; }
static void gc_free(struct gc_arena *gc) { (void)gc; }
static const char *string_alloc(const char *text, struct gc_arena *gc) { (void)gc; return text; }
static const char *print_in_addr_t(in_addr_t ip, int flags, struct gc_arena *gc)
{ (void)ip; (void)flags; (void)gc; return "10.8.0.2"; }
static const char *signal_description(int n, const char *s) { (void)n; return s; }
static void amnezia_dns_restore_before_close(const struct options *o)
{
    if (!o->amnezia_external_dns) return;
    ++restores;
    assert(!dns_down && !removed_routes && !closed && !scripts);
    if (blocked) longjmp(blocked_close, 1);
    confirmed = true;
}
static void run_dns_up_down(bool up, struct options *o, struct tuntap *tt, void *duri)
{ (void)tt; (void)duri; assert(!up); if (!o->amnezia_external_dns) ++dns_down; }
static void do_close_tun_simple(struct context *c)
{ (void)c; assert(!external || confirmed); ++closed; }
static void run_up_down(const char *command, void *plugins, int type, ...)
{ (void)command; (void)plugins; (void)type; assert(!external || confirmed); ++scripts; }
static void delete_routes(void *v4, void *v6, struct tuntap *tt, int flags, void *es, void *ctx)
{ (void)v4; (void)v6; (void)tt; (void)flags; (void)es; (void)ctx; assert(!external || confirmed); ++removed_routes; }
static void del_wfp_block(struct context *c, unsigned long index) { (void)c; (void)index; }
'''
        close_checks = r'''
int main(void)
{
    struct tuntap tt = {.actual_name = "owned-tun"};
    struct context c = {.c1 = {.tuntap = &tt, .tuntap_owned = true, .route_list = &tt}};
    struct signal_info native_signal = {SIGTERM, "test"};
    c.sig = &native_signal;
    static_context = &c;
    c.options.amnezia_external_dns = external = true;
    blocked = true;
    if (!setjmp(blocked_close)) {
        do_close_tun(&c, true);
        assert(!"Native teardown continued after unconfirmed restore");
    }
    assert(restores == 1 && !dns_down && !removed_routes && !closed && !scripts);
    assert(static_context == &c && c.c1.tuntap == &tt && c.c1.tuntap_owned);
    restores = 0; blocked = false;
    do_close_tun(&c, true);
    assert(restores == 1 && !dns_down && removed_routes == 1 && closed == 1 && scripts == 2);
    assert(static_context == NULL);
    restores = removed_routes = closed = scripts = 0; confirmed = false;
    c.options.persist_tun = true;
    c.sig->signal_received = SIGUSR1;
    do_close_tun(&c, false);
    assert(!restores && !dns_down && !removed_routes && !closed && !scripts);
    c.options.amnezia_external_dns = external = false;
    c.sig->signal_received = SIGTERM;
    do_close_tun(&c, true);
    assert(!restores && dns_down == 1 && removed_routes == 1 && closed == 1 && scripts == 2);
    restores = dns_down = removed_routes = closed = scripts = 0; confirmed = false;
    c.options.amnezia_external_dns = external = true;
    c.options.down_pre = true;
    do_close_tun(&c, true);
    assert(restores == 1 && !dns_down && removed_routes == 1 && closed == 1 && scripts == 2);
    restores = dns_down = removed_routes = closed = scripts = 0; confirmed = false;
    dco_win = true; typed = false; blocked = true;
    if (!setjmp(blocked_close)) {
        do_close_tun(&c, true);
        assert(!"Early DCO close bypassed unconfirmed restore");
    }
    assert(restores == 1 && !dns_down && !removed_routes && !closed && !scripts);
    restores = 0; blocked = false;
    do_close_tun(&c, true);
    assert(restores == 1 && !dns_down && !removed_routes && closed == 1 && !scripts);
}
'''
        (path / "close.c").write_text(close_harness + close_function + close_checks)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(path / "close.c"), "-o", str(path / "close")], check=True)
        subprocess.run([str(path / "close")], check=True)
        print("PASS: actual do_close_tun: unconfirmed restore retains ownership before routes/scripts/device teardown; confirmed cleanup; persist-tun and ON paths retained", flush=True)
        export_start = patched["dns.c"].index("void\namnezia_setenv_dns_options(")
        export_end = patched["dns.c"].index("\n}\n", export_start) + 3
        export_function = patched["dns.c"][export_start:export_end]
        export_harness = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct env_item { char *string; struct env_item *next; };
struct env_set { struct env_item *list; };
struct gc_arena { char *items[64]; int count; };
struct dns_server { struct dns_server *next; long priority; };
struct dns_options { struct dns_server *servers; const char *sni; };
static struct gc_arena gc_new(void) { return (struct gc_arena){0}; }
static char *string_alloc(const char *s, struct gc_arena *gc)
{ char *p = strdup(s); assert(p && gc->count < 64); gc->items[gc->count++] = p; return p; }
static void gc_free(struct gc_arena *gc)
{ for (int i = 0; i < gc->count; ++i) free(gc->items[i]); }
static void setenv_del(struct env_set *es, const char *key)
{
    struct env_item **item = &es->list;
    const size_t size = strlen(key);
    while (*item) {
        if (!strncmp((*item)->string, key, size) && (*item)->string[size] == '=') {
            struct env_item *dead = *item; *item = dead->next;
            free(dead->string); free(dead); return;
        }
        item = &(*item)->next;
    }
}
static void setenv_str(struct env_set *es, const char *key, const char *value)
{
    setenv_del(es, key);
    if (!value) return;
    struct env_item *item = malloc(sizeof(*item)); assert(item);
    item->string = malloc(strlen(key) + strlen(value) + 2); assert(item->string);
    sprintf(item->string, "%s=%s", key, value);
    item->next = es->list; es->list = item;
}
static const char *env_get(struct env_set *es, const char *key)
{
    for (struct env_item *item = es->list; item; item = item->next)
        if (!strncmp(item->string, key, strlen(key)) && item->string[strlen(key)] == '=')
            return item->string + strlen(key) + 1;
    return NULL;
}
static void setenv_long_long(struct env_set *es, const char *key, long long value)
{ char text[80]; snprintf(text, sizeof(text), "%lld", value); setenv_str(es, key, text); }
static void setenv_dns_options(const struct dns_options *o, struct env_set *es)
{
    if (o->servers) setenv_str(es, "dns_server_1_address_1", "192.0.2.53");
    if (o->sni) setenv_str(es, "dns_server_1_sni", o->sni);
}
'''
        export_checks = r'''
int main(void)
{
    struct env_set es = {0};
    const char *stale[] = {
        "dns_server_2_address_1", "dns_server_1_sni", "dns_search_domain_1",
        "amnezia_dns_priority_3", "amnezia_legacy_dns4_2", "amnezia_legacy_search_2"
    };
    for (size_t i = 0; i < sizeof(stale) / sizeof(*stale); ++i) setenv_str(&es, stale[i], "stale");
    setenv_str(&es, "dev", "owned-tun");
    setenv_str(&es, "foreign_option_1", "dhcp-option DNS 2001:db8::53");
    struct dns_server second = {.priority = 16};
    struct dns_server first = {.next = &second, .priority = -3};
    const struct dns_options options = {&first, "secure.example"};
    amnezia_setenv_dns_options(&options, &es);
    assert(!strcmp(env_get(&es, "dns_server_1_sni"), "secure.example"));
    assert(!strcmp(env_get(&es, "amnezia_dns_priority_1"), "-3"));
    assert(!strcmp(env_get(&es, "amnezia_dns_priority_2"), "16"));
    for (size_t i = 0; i < sizeof(stale) / sizeof(*stale); ++i)
        if (strcmp(stale[i], "dns_server_1_sni")) assert(env_get(&es, stale[i]) == NULL);
    assert(!strcmp(env_get(&es, "dev"), "owned-tun"));
    assert(!strcmp(env_get(&es, "foreign_option_1"), "dhcp-option DNS 2001:db8::53"));
    first.next = NULL;
    const struct dns_options shortened = {&first, NULL};
    amnezia_setenv_dns_options(&shortened, &es);
    assert(env_get(&es, "dns_server_1_sni") == NULL);
    assert(env_get(&es, "amnezia_dns_priority_2") == NULL);
    assert(!strcmp(env_get(&es, "dns_server_1_address_1"), "192.0.2.53"));
    assert(first.priority == -3 && second.priority == 16);
    const struct dns_options empty = {0};
    amnezia_setenv_dns_options(&empty, &es);
    assert(env_get(&es, "dns_server_1_address_1") == NULL);
    assert(env_get(&es, "amnezia_dns_priority_1") == NULL);
    assert(!strcmp(env_get(&es, "dev"), "owned-tun"));
    while (es.list) { struct env_item *item = es.list; es.list = item->next; free(item->string); free(item); }
}
'''
        (path / "export.c").write_text(export_harness + export_function + export_checks)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(path / "export.c"),
                        "-o", str(path / "export")], check=True)
        subprocess.run([str(path / "export")], check=True)
        print("PASS: actual metadata export wrapper under ASan/UBSan: priorities/order retained; shortened/empty selections remove stale SNI/servers/search/legacy fields without touching native originals/other environment", flush=True)
    print("PASS: complete cached source, checked/idempotent multi-file overlay; actual do_route ON unchanged, OFF route/publication acknowledgement failures stop initialization")


if __name__ == "__main__":
    main()
