#ifndef AMNEZIA_ROUTING_H
#define AMNEZIA_ROUTING_H
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#ifdef __APPLE__
#include <resolv.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#endif
typedef int32_t (*AmneziaPacketWriter)(void *, const uint8_t *, int32_t);
typedef void (*AmneziaHostRelease)(void *);
// Synchronous native packet filter: nonzero consumes/rejects, zero preserves
// native bytes. Never retain the borrowed packet or call FilterStop inline.
// Start consumes the retained host on success and failure. Stop joins callbacks
// before releasing it. One registration per packet-tunnel extension process.
typedef int32_t (*AmneziaPacketFilter)(void *, const uint8_t *, int32_t);
int64_t AmneziaNativePacketFilterStart(void *, AmneziaPacketFilter, AmneziaHostRelease);
void AmneziaNativePacketFilterStop(int64_t);
int32_t AmneziaNativePacketFilterFeed(uint8_t *, int32_t);
static inline int32_t amnezia_filter_packet(AmneziaPacketFilter fn, void *host, const uint8_t *data, int32_t size) { return fn(host,data,size); }
// Native DNS callbacks are asynchronous: dispatch/cancel/failure must return
// promptly, copy borrowed buffers, and never call Stop inline. All callbacks
// finish before the consumed retained host is released.
typedef int32_t (*AmneziaDNSDispatch)(void *, int64_t, uint64_t, int32_t, const uint8_t *, int32_t, int32_t);
typedef void (*AmneziaDNSCancel)(void *, int64_t, uint64_t);
typedef void (*AmneziaDNSFailure)(void *, int64_t);
int64_t AmneziaNativeDNSStart(char *, void *, AmneziaPacketWriter, AmneziaDNSDispatch, AmneziaDNSCancel, AmneziaDNSFailure, AmneziaHostRelease);
void AmneziaNativeDNSStop(int64_t);
// Feed: 1 consumed DNS, 0 native passthrough, -1 invalid/failed endpoint.
int32_t AmneziaNativeDNSFeed(int64_t, uint8_t *, int32_t);
int32_t AmneziaNativeDNSComplete(int64_t, uint64_t, uint8_t *, int32_t);
int32_t AmneziaNativeDNSReject(int64_t, uint64_t);
static inline int32_t amnezia_dns_dispatch(AmneziaDNSDispatch fn, void *host, int64_t handle, uint64_t id, int32_t network, const uint8_t *data, int32_t size, int32_t timeout) { return fn(host,handle,id,network,data,size,timeout); }
static inline void amnezia_dns_cancel(AmneziaDNSCancel fn, void *host, int64_t handle, uint64_t id) { fn(host,handle,id); }
static inline void amnezia_dns_failure(AmneziaDNSFailure fn, void *host, int64_t handle) { fn(host,handle); }
// Start consumes the retained host even when it fails. Only packet buffers are
// borrowed; both sides copy before returning. No config/error text is logged.
int64_t AmneziaRoutingStart(char *, int32_t, void *, AmneziaPacketWriter, AmneziaHostRelease);
void AmneziaRoutingStop(int64_t);
int32_t AmneziaRoutingFeed(int64_t, uint8_t *, int32_t);
// Diagnostics returns owned UTF-8 JSON; caller must free it.
char *AmneziaRoutingDiagnostics(int64_t);
// Owned build identifiers only; caller frees with free().
char *AmneziaRoutingBuildInfo(void);
// Owned JSON array of the public system resolver's numeric servers; free().
char *AmneziaRoutingSystemDNS(void);
int32_t AmneziaRoutingValidate(char *,int32_t);
int32_t AmneziaRoutingStats(int64_t, uint64_t *, uint64_t *, uint64_t *);
static inline int32_t amnezia_write_packet(AmneziaPacketWriter fn, void *host, const uint8_t *data, int32_t size) { return fn(host, data, size); }
static inline void amnezia_release_host(AmneziaHostRelease fn, void *host) { fn(host); }
static inline char *amnezia_system_dns(void) {
#ifdef __APPLE__
    struct __res_state state; memset(&state,0,sizeof(state));
    if(res_ninit(&state)!=0)return NULL;
    union res_sockaddr_union servers[16];
    int count=res_getservers(&state,servers,16);
    char *json=calloc(4096,1);size_t used=0;
    if(json){json[used++]='[';
        for(int i=0;i<count && i<16;i++){
            char ip[INET6_ADDRSTRLEN+24];void *address=NULL;unsigned short port=0;
            if(servers[i].sin.sin_family==AF_INET){address=&servers[i].sin.sin_addr;port=ntohs(servers[i].sin.sin_port);}
            else if(servers[i].sin6.sin6_family==AF_INET6){address=&servers[i].sin6.sin6_addr;port=ntohs(servers[i].sin6.sin6_port);}
            if(!address || !inet_ntop(servers[i].sin.sin_family,address,ip,sizeof(ip)))continue;
            if(servers[i].sin.sin_family==AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&servers[i].sin6.sin6_addr) && servers[i].sin6.sin6_scope_id){size_t n=strlen(ip);snprintf(ip+n,sizeof(ip)-n,"%%%u",servers[i].sin6.sin6_scope_id);}
            int n=snprintf(json+used,4096-used,"%s{\"address\":\"%s\",\"port\":%u}",used>1?",":"",ip,port?port:53);
            if(n<0 || (size_t)n>=4096-used){free(json);json=NULL;break;}used+=(size_t)n;
        }
        if(json){json[used++]=']';json[used]=0;}
    }
    res_ndestroy(&state);return json;
#else
    return NULL;
#endif
}
static inline int amnezia_bind_dns_interface(int fd,const char *name) {
#ifdef __APPLE__
    unsigned int index=if_nametoindex(name);if(!index)return -1;
    struct sockaddr_storage local;socklen_t length=sizeof(local);
    if(getsockname(fd,(struct sockaddr *)&local,&length)!=0)return -1;
    if(local.ss_family==AF_INET)return setsockopt(fd,IPPROTO_IP,IP_BOUND_IF,&index,sizeof(index));
    if(local.ss_family==AF_INET6)return setsockopt(fd,IPPROTO_IPV6,IPV6_BOUND_IF,&index,sizeof(index));
#else
    (void)fd;
    (void)name;
#endif
    return -1;
}
#endif
