#ifndef AMNEZIA_OPENVPN_NATIVE_DNS_H
#define AMNEZIA_OPENVPN_NATIVE_DNS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Callback bytes are borrowed only for the call. Dispatch/write/cancel/failure
 * must enqueue or return promptly; never synchronously Stop their own owner.
 * Release is delivered exactly once, after every callback has joined. */
typedef int32_t (*AmneziaOVPNPacketWriter)(void *, const uint8_t *, int32_t);
typedef int32_t (*AmneziaOVPNDNSDispatch)(void *, int64_t, uint64_t, int32_t,
                                       const uint8_t *, int32_t, int32_t);
typedef void (*AmneziaOVPNDNSCancel)(void *, int64_t, uint64_t);
typedef void (*AmneziaOVPNDNSFailure)(void *, int64_t);
typedef void (*AmneziaOVPNHostRelease)(void *);
typedef int32_t (*AmneziaOVPNDNSBind)(void *, int64_t, int32_t);

/* Policy is pinned before native bootstrap. Release confirms engine/DNS join
 * but retains the effective fence until the next explicit connection policy. */
int64_t AmneziaOpenVPNDNSPolicy(int32_t);
int32_t AmneziaOpenVPNDNSReleasePolicy(int64_t);
int32_t AmneziaOpenVPNDNSIPv6Off(void);
int64_t AmneziaOpenVPNDNSStart(char *, int64_t, void *, AmneziaOVPNPacketWriter,
                             AmneziaOVPNDNSDispatch, AmneziaOVPNDNSCancel,
                             AmneziaOVPNDNSFailure, AmneziaOVPNHostRelease);
int64_t AmneziaOpenVPNDNSStartScoped(char *, char *, int64_t, void *,
                                   AmneziaOVPNPacketWriter, AmneziaOVPNDNSBind,
                                   AmneziaOVPNDNSFailure, AmneziaOVPNHostRelease);
int32_t AmneziaOpenVPNDNSFeed(int64_t, uint8_t *, int32_t);
int32_t AmneziaOpenVPNDNSComplete(int64_t, uint64_t, uint8_t *, int32_t);
int32_t AmneziaOpenVPNDNSReject(int64_t, uint64_t);
/* Every concurrent Stop of a live handle waits for the same confirmed join. */
int32_t AmneziaOpenVPNDNSStop(int64_t);
int32_t AmneziaOpenVPNDNSQuiesce(int64_t);
int32_t AmneziaOpenVPNDNSResume(int64_t);
int64_t AmneziaOpenVPNDNSStartSelected(char *, char *, char *, char *, char *, int64_t,
    void *, AmneziaOVPNPacketWriter, AmneziaOVPNDNSBind, AmneziaOVPNDNSFailure, AmneziaOVPNHostRelease);
/* Tunnel writer goes into the existing engine, NEVER the kernel TUN. */
int64_t AmneziaOpenVPNDNSStartTunnel(char *, char *, char *, char *, char *, char *, int32_t, int64_t,
    void *, AmneziaOVPNPacketWriter, AmneziaOVPNPacketWriter, AmneziaOVPNDNSFailure, AmneziaOVPNHostRelease);
int32_t AmneziaOpenVPNDNSFeedTunnel(int64_t, uint8_t *, int32_t);
/* Caller frees the returned JSON with free(). No connection/user data. */
char *AmneziaOpenVPNDNSProvenance(void);

static inline int32_t amnezia_ovpn_dns_write(AmneziaOVPNPacketWriter cb, void *host,
                                            const uint8_t *bytes, int32_t size)
{ return cb(host, bytes, size); }
static inline int32_t amnezia_ovpn_dns_dispatch(AmneziaOVPNDNSDispatch cb, void *host,
                                               int64_t handle, uint64_t token, int32_t network,
                                               const uint8_t *bytes, int32_t size, int32_t timeout)
{ return cb(host, handle, token, network, bytes, size, timeout); }
static inline void amnezia_ovpn_dns_cancel(AmneziaOVPNDNSCancel cb, void *host,
                                          int64_t handle, uint64_t token)
{ cb(host, handle, token); }
static inline void amnezia_ovpn_dns_failed(AmneziaOVPNDNSFailure cb, void *host, int64_t handle)
{ cb(host, handle); }
static inline void amnezia_ovpn_dns_release(AmneziaOVPNHostRelease cb, void *host)
{ cb(host); }
static inline int32_t amnezia_ovpn_dns_bind(AmneziaOVPNDNSBind cb, void *host, int64_t handle, int32_t fd)
{ return cb(host, handle, fd); }

#ifdef __cplusplus
}
#endif
#endif
