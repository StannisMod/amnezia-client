#ifndef AMNEZIA_ROUTING_H
#define AMNEZIA_ROUTING_H
#include <stdint.h>
#include <stddef.h>
typedef int32_t (*AmneziaPacketWriter)(void *, const uint8_t *, int32_t);
typedef void (*AmneziaHostRelease)(void *);
// Start consumes the retained host even when it fails. Only packet buffers are
// borrowed; both sides copy before returning. No config/error text is logged.
int64_t AmneziaRoutingStart(char *, int32_t, void *, AmneziaPacketWriter, AmneziaHostRelease);
void AmneziaRoutingStop(int64_t);
int32_t AmneziaRoutingFeed(int64_t, uint8_t *, int32_t);
int32_t AmneziaRoutingStats(int64_t, uint64_t *, uint64_t *, uint64_t *);
static inline int32_t amnezia_write_packet(AmneziaPacketWriter fn, void *host, const uint8_t *data, int32_t size) { return fn(host, data, size); }
static inline void amnezia_release_host(AmneziaHostRelease fn, void *host) { fn(host); }
#endif
