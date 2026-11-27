#include "hev-main.h"
#include <assert.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned ready, filtered;
static int descriptors[2];
static int result = -99;

void amnezia_hev_ready(void) {
    pthread_mutex_lock(&lock);
    ready++;
    pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&lock);
}

int32_t AmneziaNativePacketFilterFeed(uint8_t *packet, int32_t size) {
    assert(size == 40 && packet[0] == 0x60);
    pthread_mutex_lock(&lock);
    filtered++;
    pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&lock);
    return 1; /* The fixture must never create a SOCKS or upstream connection. */
}

static void wait_count(unsigned *counter, unsigned count) {
    struct timespec deadline;
    assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 5;
    pthread_mutex_lock(&lock);
    while (*counter < count)
        assert(pthread_cond_timedwait(&changed, &lock, &deadline) == 0);
    pthread_mutex_unlock(&lock);
}

static void *run(void *unused) {
    (void)unused;
    const unsigned char config[] =
        "tunnel:\n  mtu: 1280\n"
        "socks5:\n  address: 127.0.0.1\n  port: 9\n  udp: udp\n"
        "misc:\n  log-level: error\n  limit-nofile: 128\n";
    result = hev_socks5_tunnel_main_from_str(config, sizeof(config) - 1, descriptors[0]);
    return NULL;
}

int main(void) {
    amnezia_hev_filter_enable(1);
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, descriptors) == 0);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, run, NULL) == 0);
    wait_count(&ready, 1);
    uint8_t packet[44] = {0};
    uint32_t family = htonl(AF_INET6);
    memcpy(packet, &family, sizeof(family));
    packet[4] = 0x60;
    assert(write(descriptors[1], packet, sizeof(packet)) == (ssize_t)sizeof(packet));
    wait_count(&filtered, 1);
    hev_socks5_tunnel_quit();
    assert(pthread_join(thread, NULL) == 0);
    assert(result == 0 && ready == 1 && filtered == 1);
    /* A late quit must not spin on the now retired event fd. */
    hev_socks5_tunnel_quit();
    close(descriptors[0]);
    close(descriptors[1]);
    puts("PASS: actual host HEV reader filter, readiness, joined Stop and retired event-fd safety");
    return 0;
}
