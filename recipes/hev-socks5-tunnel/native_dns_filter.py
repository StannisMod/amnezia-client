"""Checked hooks for the project's static Apple HEV framework."""

READ = """        buf = hev_tunnel_read (tun_fd, mtu, task_io_yielder, NULL);
        if (!buf)
            continue;
"""
FILTERED_READ = READ + """
        /* AMNEZIA_NATIVE_DNS_FILTER: input PBUF_RAM is contiguous. */
        if (__atomic_load_n (&amnezia_hev_filter_enabled, __ATOMIC_ACQUIRE) &&
            (buf->len != buf->tot_len ||
             AmneziaNativePacketFilterFeed (buf->payload, buf->len))) {
            pbuf_free (buf);
            continue;
        }
"""
HEADER = '#include "hev-tunnel.h"\n'
DECLARATIONS = HEADER + """
#include <stdint.h>
#include <pthread.h>
extern int32_t AmneziaNativePacketFilterFeed (uint8_t *, int32_t);
extern void amnezia_hev_ready (void);
static pthread_mutex_t amnezia_hev_stop_lock = PTHREAD_MUTEX_INITIALIZER;
static int amnezia_hev_filter_enabled;
void
amnezia_hev_filter_enable (int enabled)
{
    __atomic_store_n (&amnezia_hev_filter_enabled, enabled != 0, __ATOMIC_RELEASE);
}
"""
READY = "    run = 1;\n    hev_task_system_run ();"
READY_HOOK = "    run = 1;\n    amnezia_hev_ready ();\n    hev_task_system_run ();"
FINI = "static void\nevent_task_fini (void)\n{\n"
FINI_LOCK = FINI + "    pthread_mutex_lock (&amnezia_hev_stop_lock);\n"
FINI_END = "        event_fds[1] = -1;\n    }\n}"
FINI_UNLOCK = "        event_fds[1] = -1;\n    }\n    pthread_mutex_unlock (&amnezia_hev_stop_lock);\n}"
STOP = """void
hev_socks5_tunnel_stop (void)
{
    int res = 0;
    int fd;

    LOG_D ("socks5 tunnel stop");

    for (;;) {
        fd = READ_ONCE (event_fds[1]);
        if (fd >= 0)
            break;
        /* Wait for async initialization */
        usleep (100 * 1000);
    }

    res = write (fd, &res, 1);
    assert (res > 0 && "socks5 tunnel write event");
}"""
JOINED_STOP = """void
hev_socks5_tunnel_stop (void)
{
    int res = 0;
    int fd;

    LOG_D ("socks5 tunnel stop");
    /* Swift remembers early Stop until readiness. Serialize a late Stop with
     * descriptor retirement, so it cannot spin on or write a reused fd. */
    pthread_mutex_lock (&amnezia_hev_stop_lock);
    fd = event_fds[1];
    if (fd >= 0) {
        do {
            res = write (fd, &res, 1);
        } while (res < 0 && errno == EINTR);
        assert (res > 0 && "socks5 tunnel write event");
    }
    pthread_mutex_unlock (&amnezia_hev_stop_lock);
}"""


def prepare(text):
    changes = [(HEADER, DECLARATIONS), (READ, FILTERED_READ), (READY, READY_HOOK),
               (FINI, FINI_LOCK), (FINI_END, FINI_UNLOCK), (STOP, JOINED_STOP)]
    if "AMNEZIA_NATIVE_DNS_FILTER" in text:
        if not all(text.count(after) == 1 for _, after in changes):
            raise RuntimeError("Inconsistent native HEV DNS/lifecycle overlay")
        return text
    if not all(text.count(before) == 1 for before, _ in changes):
        raise RuntimeError("Unexpected native HEV reader/lifecycle entry point")
    for before, after in changes:
        text = text.replace(before, after)
    return text


HEADER_ENTRY = "int hev_socks5_tunnel_main (const char *config_path, int tun_fd);"
HEADER_REPLACEMENT = HEADER_ENTRY + """

/* Project Apple framework: configure only within the owned native run. */
void amnezia_hev_filter_enable (int enabled);"""


def prepare_header(text):
    if HEADER_REPLACEMENT in text:
        if text.count(HEADER_REPLACEMENT) != 1:
            raise RuntimeError("Inconsistent HEV native filter declaration")
        return text
    if text.count(HEADER_ENTRY) != 1:
        raise RuntimeError("Unexpected HEV public framework header")
    return text.replace(HEADER_ENTRY, HEADER_REPLACEMENT)
