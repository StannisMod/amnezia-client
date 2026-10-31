#ifndef AMNEZIA_ROUTING_HOST_H
#define AMNEZIA_ROUTING_HOST_H
#include <stdint.h>
int amnezia_routing_protect(uintptr_t host, int fd);
char *amnezia_routing_interfaces(uintptr_t host);
void amnezia_routing_release(uintptr_t host);
#endif
