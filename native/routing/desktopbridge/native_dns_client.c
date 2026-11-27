#include "amnezia_xray.h"
#include <assert.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void read_all(int fd, void *bytes, size_t size) {
    unsigned char *data = bytes;
    while (size) {
        ssize_t n = read(fd, data, size);
        assert(n > 0);
        data += n;
        size -= (size_t)n;
    }
}

static void query(const char *address, int tcp, unsigned type, unsigned rcode) {
    int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct timeval timeout = {.tv_sec = 2};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    struct sockaddr_in server = {.sin_family = AF_INET, .sin_port = htons(53)};
    assert(inet_pton(AF_INET, address, &server.sin_addr) == 1);
    assert(connect(fd, (struct sockaddr *)&server, sizeof(server)) == 0);
    unsigned char request[] = {
        0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0,
        0, 0, 0, 1
    };
    request[sizeof(request) - 3] = (unsigned char)type;
    uint16_t length = htons(sizeof(request));
    if (tcp) assert(write(fd, &length, sizeof(length)) == (ssize_t)sizeof(length));
    assert(write(fd, request, sizeof(request)) == (ssize_t)sizeof(request));
    unsigned char response[4096];
    ssize_t size;
    if (tcp) {
        read_all(fd, &length, sizeof(length));
        size = ntohs(length);
        assert(size <= (ssize_t)sizeof(response));
        read_all(fd, response, (size_t)size);
    } else {
        size = read(fd, response, sizeof(response));
    }
    assert(size >= 12 && response[0] == 0x12 && response[1] == 0x34);
    assert((response[2] & 0x80) != 0 && (response[3] & 15) == rcode);
    assert(response[6] == 0 && response[7] == 0);
    close(fd);
}

int main(void) {
    unsigned index = if_nametoindex("dns-fixture");
    assert(index > 0);
    char config[512];
    int count = snprintf(config, sizeof(config),
        "{\"bindings\":[{\"endpoint\":\"192.0.2.10:53\","
        "\"upstream\":\"[2001:db8::53]:53\","
        "\"interface_name\":\"dns-fixture\",\"interface_index\":%u}]}", index);
    assert(count > 0 && count < (int)sizeof(config));
    assert(amnezia_native_dns_start("{\"bindings\":[],\"fallback\":\"8.8.8.8\"}") < 0);
    int64_t handle = amnezia_native_dns_start(config);
    assert(handle > 0 && amnezia_native_dns_alive(handle) == 1);
    assert(amnezia_native_dns_start(config) < 0);
    query("192.0.2.10", 0, 28, 0);
    query("192.0.2.10", 1, 28, 0);
    query("192.0.2.10", 0, 1, 2); /* IPv6-only original DNS: fail, never substitute IPv4. */
    query("192.0.2.10", 1, 1, 2);
    char replacement[512];
    count = snprintf(replacement, sizeof(replacement),
        "{\"bindings\":[{\"endpoint\":\"127.0.0.1:53\","
        "\"upstream\":\"[2001:db8::53]:53\","
        "\"interface_name\":\"dns-fixture\",\"interface_index\":%u}]}", index);
    assert(count > 0 && count < (int)sizeof(replacement));
    int64_t prepared = amnezia_native_dns_start(replacement);
    assert(prepared > handle);
    assert(amnezia_native_dns_alive(prepared) == 1);
    query("127.0.0.1", 0, 28, 0);
    query("192.0.2.10", 1, 28, 0); /* Old published generation still works. */
    assert(amnezia_native_dns_stop(prepared + 1) == 0);
    assert(amnezia_native_dns_alive(handle) == 1);
    assert(amnezia_native_dns_quiesce(handle) == 1);
    assert(amnezia_native_dns_quiesce(handle) == 1);
    assert(amnezia_native_dns_alive(handle) == 1);
    query("192.0.2.10", 0, 28, 0);
    query("192.0.2.10", 1, 28, 0);
    query("192.0.2.10", 0, 1, 2);
    query("192.0.2.10", 1, 1, 2);
    assert(amnezia_native_dns_stop(handle) == 1);
    assert(amnezia_native_dns_alive(handle) == 0);
    assert(amnezia_native_dns_stop(handle) == 0);
    assert(amnezia_native_dns_quiesce(handle) == 0);
    assert(amnezia_native_dns_alive(prepared) == 1);
    query("127.0.0.1", 1, 28, 0);
    assert(amnezia_native_dns_stop(prepared) == 1);
    int64_t next = amnezia_native_dns_start(config);
    assert(next > handle);
    assert(amnezia_native_dns_stop(handle) == 0);
    assert(amnezia_native_dns_alive(next) == 1);
    assert(amnezia_native_dns_stop(next) == 1);
    puts("PASS: existing desktop Xray Go runtime DNS C ABI, UDP/TCP NODATA, IPv6-only failure, prepared/published generations and joined/stale-handle Stop");
    return 0;
}
