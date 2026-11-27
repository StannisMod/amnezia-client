#include "amnezia_routing.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned writes, dispatches, cancels, releases, failures;
    int delayed, reject;
    uint64_t token;
} Host;

static void wait_count(Host *h, unsigned *counter, unsigned target) {
    struct timespec until;
    assert(clock_gettime(CLOCK_REALTIME, &until) == 0);
    until.tv_sec += 5;
    pthread_mutex_lock(&h->lock);
    while (*counter < target)
        assert(pthread_cond_timedwait(&h->changed, &h->lock, &until) == 0);
    pthread_mutex_unlock(&h->lock);
}

static int32_t writer(void *ctx, const uint8_t *packet, int32_t size) {
    Host *h = ctx;
    assert(size >= 40 && (packet[0] >> 4) == 4 && packet[9] == 17);
    unsigned header = (packet[0] & 15) * 4;
    assert(header >= 20 && size >= (int32_t)(header + 20));
    const uint8_t *dns = packet + header + 8;
    assert((dns[2] & 0x80) != 0);
    unsigned id = (dns[0] << 8) | dns[1];
    assert((dns[3] & 15) == (id == 0x1237 ? 2 : 0) && (dns[3] & 0x20) == 0);
    assert(dns[6] == 0 && dns[7] == 0); /* NODATA */
    pthread_mutex_lock(&h->lock);
    assert(h->releases == 0);
    h->writes++;
    pthread_cond_broadcast(&h->changed);
    pthread_mutex_unlock(&h->lock);
    return 1;
}

static int32_t dispatch(void *ctx, int64_t handle, uint64_t token, int32_t network,
                        const uint8_t *request, int32_t size, int32_t timeout) {
    Host *h = ctx;
    assert(network == 0 && size >= 12 && size <= 65535 && timeout > 0 && timeout <= 5000);
    pthread_mutex_lock(&h->lock);
    assert(h->releases == 0);
    h->dispatches++;
    h->token = token;
    int delayed = h->delayed;
    int reject = h->reject;
    pthread_cond_broadcast(&h->changed);
    pthread_mutex_unlock(&h->lock);
    if (reject) {
        assert(AmneziaNativeDNSReject(handle, token) == 1);
        assert(AmneziaNativeDNSReject(handle, token) == 0);
    } else if (!delayed) {
        uint8_t *answer = malloc((size_t)size);
        assert(answer != NULL);
        memcpy(answer, request, (size_t)size);
        answer[2] |= 0x80;
        answer[3] = 0x80;
        assert(AmneziaNativeDNSComplete(handle, token, answer, size) == 1);
        assert(AmneziaNativeDNSComplete(handle, token, answer, size) == 0);
        memset(answer, 0, (size_t)size);
        free(answer);
    }
    return 1;
}

static void cancel_request(void *ctx, int64_t handle, uint64_t token) {
    (void)handle;
    Host *h = ctx;
    pthread_mutex_lock(&h->lock);
    assert(h->releases == 0 && token == h->token);
    h->cancels++;
    pthread_cond_broadcast(&h->changed);
    pthread_mutex_unlock(&h->lock);
}

static void failed(void *ctx, int64_t handle) {
    (void)handle;
    Host *h = ctx;
    pthread_mutex_lock(&h->lock);
    assert(h->releases == 0);
    h->failures++;
    pthread_cond_broadcast(&h->changed);
    pthread_mutex_unlock(&h->lock);
}

static void release_host(void *ctx) {
    Host *h = ctx;
    pthread_mutex_lock(&h->lock);
    if (h->delayed) assert(h->cancels == 1);
    h->releases++;
    pthread_cond_broadcast(&h->changed);
    pthread_mutex_unlock(&h->lock);
}

static int32_t filter_packet(void *ctx, const uint8_t *packet, int32_t size) {
    Host *h = ctx;
    assert(size >= 1);
    pthread_mutex_lock(&h->lock);
    assert(h->releases == 0);
    h->dispatches++;
    pthread_cond_broadcast(&h->changed);
    while (h->delayed) pthread_cond_wait(&h->changed, &h->lock);
    assert(h->releases == 0);
    pthread_mutex_unlock(&h->lock);
    return (packet[0] >> 4) == 6;
}

typedef struct { Host *host; int64_t handle; } FilterThread;
static void *feed_filter(void *unused) {
    (void)unused;
    uint8_t packet[] = {0x60, 0, 0, 0};
    assert(AmneziaNativePacketFilterFeed(packet, sizeof(packet)) == 1);
    return NULL;
}
static void *stop_filter(void *arg) {
    FilterThread *thread = arg;
    pthread_mutex_lock(&thread->host->lock);
    thread->host->cancels++;
    pthread_cond_broadcast(&thread->host->changed);
    pthread_mutex_unlock(&thread->host->lock);
    AmneziaNativePacketFilterStop(thread->handle);
    return NULL;
}

static void put16(uint8_t *p, unsigned value) { p[0] = value >> 8; p[1] = value; }

static unsigned packet(uint8_t *p, unsigned id, unsigned type) {
    const uint8_t name[] = {7,'m','a','n','a','g','e','d',7,'e','x','a','m','p','l','e',0};
    unsigned total = 20 + 8 + 12 + sizeof(name) + 4;
    memset(p, 0, total);
    p[0] = 0x45;
    put16(p + 2, total);
    p[8] = 64; p[9] = 17;
    p[12] = 10; p[13] = 77; p[15] = 2;
    p[16] = 172; p[17] = 19; p[19] = 2;
    put16(p + 20, 40000); put16(p + 22, 53);
    put16(p + 24, total - 20); /* IPv4 UDP checksum zero is valid. */
    uint8_t *q = p + 28;
    put16(q, id); q[2] = 1; put16(q + 4, 1);
    memcpy(q + 12, name, sizeof(name));
    put16(q + 12 + sizeof(name), type); put16(q + 14 + sizeof(name), 1);
    unsigned sum = 0;
    for (unsigned i = 0; i < 20; i += 2) sum += (p[i] << 8) | p[i + 1];
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    put16(p + 10, (~sum) & 65535);
    return total;
}

int main(void) {
    Host h = {.lock = PTHREAD_MUTEX_INITIALIZER, .changed = PTHREAD_COND_INITIALIZER};
    int64_t handle = AmneziaNativeDNSStart("172.19.0.2", &h, writer, dispatch, cancel_request, failed, release_host);
    assert(handle > 0);
    uint8_t wire[512];
    unsigned size = packet(wire, 0x1234, 28);
    assert(AmneziaNativeDNSFeed(handle, wire, (int32_t)size) == 1);
    wait_count(&h, &h.writes, 1);
    assert(h.dispatches == 0);
    size = packet(wire, 0x1235, 1);
    assert(AmneziaNativeDNSFeed(handle, wire, (int32_t)size) == 1);
    wait_count(&h, &h.writes, 2);
    assert(h.dispatches == 1);
    wire[16] = 198; wire[17] = 51; wire[18] = 100; wire[19] = 2;
    assert(AmneziaNativeDNSFeed(handle, wire, (int32_t)size) == 0);
    pthread_mutex_lock(&h.lock);
    h.reject = 1;
    pthread_mutex_unlock(&h.lock);
    size = packet(wire, 0x1237, 1);
    assert(AmneziaNativeDNSFeed(handle, wire, (int32_t)size) == 1);
    wait_count(&h, &h.writes, 3);
    pthread_mutex_lock(&h.lock);
    h.reject = 0;
    h.delayed = 1;
    pthread_mutex_unlock(&h.lock);
    size = packet(wire, 0x1236, 1);
    assert(AmneziaNativeDNSFeed(handle, wire, (int32_t)size) == 1);
    wait_count(&h, &h.dispatches, 3);
    AmneziaNativeDNSStop(handle);
    assert(h.cancels == 1 && h.releases == 1 && h.failures == 0);
    assert(AmneziaNativeDNSComplete(handle, h.token, wire + 28, (int32_t)size - 28) == 0);
    assert(AmneziaNativeDNSFeed(handle, wire, (int32_t)size) == -1);
    AmneziaNativeDNSStop(handle);
    assert(h.releases == 1);
    assert(AmneziaNativeDNSStart("172.19.0.2", &h, NULL, dispatch, cancel_request, failed, release_host) < 0);
    assert(h.releases == 2);
    pthread_cond_destroy(&h.changed);
    pthread_mutex_destroy(&h.lock);
    Host filter = {.lock = PTHREAD_MUTEX_INITIALIZER, .changed = PTHREAD_COND_INITIALIZER, .delayed = 1};
    Host rejected = {.lock = PTHREAD_MUTEX_INITIALIZER, .changed = PTHREAD_COND_INITIALIZER};
    int64_t filter_handle = AmneziaNativePacketFilterStart(&filter, filter_packet, release_host);
    assert(filter_handle > 0);
    assert(AmneziaNativePacketFilterStart(&rejected, filter_packet, release_host) < 0);
    assert(rejected.releases == 1);
    pthread_t feeding, stopping;
    FilterThread thread = {.host = &filter, .handle = filter_handle};
    assert(pthread_create(&feeding, NULL, feed_filter, NULL) == 0);
    wait_count(&filter, &filter.dispatches, 1);
    assert(pthread_create(&stopping, NULL, stop_filter, &thread) == 0);
    wait_count(&filter, &filter.cancels, 1);
    pthread_mutex_lock(&filter.lock);
    assert(filter.releases == 0);
    filter.delayed = 0;
    pthread_cond_broadcast(&filter.changed);
    pthread_mutex_unlock(&filter.lock);
    assert(pthread_join(feeding, NULL) == 0);
    assert(pthread_join(stopping, NULL) == 0);
    assert(filter.releases == 1);
    AmneziaNativePacketFilterStop(filter_handle);
    assert(filter.releases == 1);
    uint8_t native[] = {0x45, 0, 0, 0};
    assert(AmneziaNativePacketFilterFeed(native, sizeof(native)) == 0);
    pthread_cond_destroy(&filter.changed);
    pthread_mutex_destroy(&filter.lock);
    pthread_cond_destroy(&rejected.changed);
    pthread_mutex_destroy(&rejected.lock);
    puts("PASS: DNS C ABI NODATA/forwarding, packet scope, cancellation and retained-host lifetime");
    puts("PASS: native TUN filter scope, duplicate admission and in-flight callback lifetime");
    return 0;
}
