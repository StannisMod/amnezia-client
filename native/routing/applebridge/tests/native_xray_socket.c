#include "amnezia_routing.h"
#include <assert.h>
#include <unistd.h>

int main(void) {
    unsigned index = if_nametoindex("lo0");
    assert(index > 0);
    int v4 = socket(AF_INET, SOCK_DGRAM, 0);
    int v6 = socket(AF_INET6, SOCK_DGRAM, 0);
    assert(v4 >= 0 && v6 >= 0);
    assert(amnezia_bind_xray_interface(v4, 0, 1) != 0);
    assert(amnezia_bind_xray_interface(v4, index, 1) == 0);
    unsigned bound = 0;
    socklen_t length = sizeof(bound);
    assert(getsockopt(v4, IPPROTO_IP, IP_BOUND_IF, &bound, &length) == 0);
    assert(bound == index);
    assert(amnezia_bind_xray_interface(v6, index, 1) != 0);
    assert(amnezia_bind_xray_interface(v6, index, 0) == 0);
    length = sizeof(bound);
    assert(getsockopt(v6, IPPROTO_IPV6, IPV6_BOUND_IF, &bound, &length) == 0);
    assert(bound == index);
    close(v4);
    close(v6);
    assert(amnezia_bind_xray_interface(v4, index, 0) != 0);
    puts("PASS: real native Xray IPv4 scope, IPv6-OFF rejection, ON IPv6 scope and bind errors");
    return 0;
}
