#ifndef AMNEZIA_ROUTING_HOST_H
#define AMNEZIA_ROUTING_HOST_H
#include <stdint.h>
int amnezia_routing_protect(uintptr_t host, int fd);
int amnezia_routing_protect_interface(uintptr_t host,int fd,const char *name);
char *amnezia_routing_interfaces(uintptr_t host);
void amnezia_routing_release(uintptr_t host);
int amnezia_routing_has_owner(uintptr_t host);
int amnezia_routing_owner(uintptr_t host, int protocol, const char *source, int source_port, const char *destination, int destination_port);
#endif
