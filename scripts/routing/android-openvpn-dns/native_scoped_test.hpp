#ifndef AMNEZIA_OPENVPN_DNS_NATIVE_SCOPED_TEST_HPP
#define AMNEZIA_OPENVPN_DNS_NATIVE_SCOPED_TEST_HPP
#include <netinet/in.h>
#include <cstdlib>
namespace {
void testSelectedEncryptedForwarding()
{
    const auto dot=std::getenv("AMNEZIA_TEST_DOT");
    const auto doh=std::getenv("AMNEZIA_TEST_DOH");
    const auto uri=std::getenv("AMNEZIA_TEST_DOH_URL");
    assert(dot && doh && uri);
    std::atomic<unsigned> binds{0},retired{0};
    amnezia::NativeDNSCallbacks callbacks{};
    callbacks.bind=[&](int64_t,int fd){
        int domain=0,type=0;socklen_t size=sizeof(domain);
        assert(getsockopt(fd,SOL_SOCKET,SO_DOMAIN,&domain,&size)==0 && domain==AF_INET);
        size=sizeof(type);
        assert(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size)==0 && type==SOCK_STREAM);
        sockaddr_storage peer{};size=sizeof(peer);
        assert(getpeername(fd,reinterpret_cast<sockaddr *>(&peer),&size)<0 && errno==ENOTCONN);
        binds++;return true;
    };
    callbacks.retired=[&](int64_t){retired++;};
    amnezia::NativeDNSState state(callbacks);Capture capture;
    assert(state.policy(true));
    for(const auto &transport:{std::string("tls"),std::string("https")}){
        state.begin();
        assert(state.prepareSelected("198.19.255.1",transport=="tls"?dot:doh,transport,
            "selected.invalid",transport=="tls"?"":uri)>0);
        assert(state.attach(capture.fd[0],false));
        const auto before=binds.load();
        auto wire=packet(0x3490,28);assert(state.feed(wire.data(),wire.size())==1);
        receive(capture.fd[1],0x3490,0,false);assert(binds==before);
        wire=packet(0x3491,1);assert(state.feed(wire.data(),wire.size())==1);
        receive(capture.fd[1],0x3491,0,true);
        TCPPeer peer(state,capture.fd[1]);
        auto nodata=peer.query(0x3492,28);assert(nodata[7]==0);
        auto answer=peer.query(0x3493,1);
        assert(answer[7]==1 && (answer[3]&0x20));peer.close();
        assert(binds==before+2);
        state.stop();
        state.begin();
        assert(state.prepareSelected("198.19.255.1",transport=="tls"?dot:doh,transport,
            "wrong.invalid",transport=="tls"?"":uri)>0);
        assert(state.attach(capture.fd[0],false));
        wire=packet(0x3494,1);assert(state.feed(wire.data(),wire.size())==1);
        receive(capture.fd[1],0x3494,2,false); // REAL TLS name mismatch, never plaintext fallback.
        assert(binds==before+3);state.stop();
    }
    assert(retired==4 && state.releasePolicy());
}
void testSelectedEncryptedScopesNeverDowngrade()
{
    std::atomic<unsigned> binds{0},retired{0};
    amnezia::NativeDNSCallbacks callbacks{};
    callbacks.bind=[&](int64_t,int fd){
        int domain=0,type=0;socklen_t size=sizeof(domain);
        assert(getsockopt(fd,SOL_SOCKET,SO_DOMAIN,&domain,&size)==0 && domain==AF_INET);
        size=sizeof(type);
        assert(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size)==0 && type==SOCK_STREAM);
        binds++;return false;
    };
    callbacks.retired=[&](int64_t){retired++;};
    amnezia::NativeDNSState state(callbacks);Capture capture;
    assert(state.policy(true));state.begin();
    assert(state.prepareSelected("198.19.255.1","192.0.2.53:853","","","")<0);
    assert(state.prepareSelected("198.19.255.1","192.0.2.53:853","opportunistic","","")<0);
    assert(state.prepareSelected("198.19.255.1","192.0.2.53:53","plain","selected.invalid","")<0);
    assert(binds==0);
    for(const auto &transport:{std::string("tls"),std::string("https")}){
        for(const auto &server:{std::string("[fd77::53]:853"),std::string("192.0.2.53:853")}){
            state.begin();
            const auto uri=transport=="https"?"https://selected.invalid:853/dns-query":"";
            assert(state.prepareSelected("198.19.255.1",server,transport,"selected.invalid",uri)>0);
            assert(state.attach(capture.fd[0],false));
            const auto before=binds.load();
            auto wire=packet(0x3480,28);assert(state.feed(wire.data(),wire.size())==1);
            receive(capture.fd[1],0x3480,0,false);assert(binds==before);
            wire=packet(0x3481,1);assert(state.feed(wire.data(),wire.size())==1);
            receive(capture.fd[1],0x3481,2,false);
            TCPPeer peer(state,capture.fd[1]);peer.query(0x3482,1,2);peer.close();
            assert(binds==before+(server.front()=='['?0:2));
            state.stop();
        }
    }
    assert(retired==4 && state.releasePolicy());
}
void testScopedBlockedBindRetirement()
{
    int upstream=socket(AF_INET,SOCK_DGRAM,0); assert(upstream>=0);
    sockaddr_in address{}; address.sin_family=AF_INET;
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    assert(bind(upstream,reinterpret_cast<sockaddr *>(&address),sizeof(address))==0);
    socklen_t length=sizeof(address);
    assert(getsockname(upstream,reinterpret_cast<sockaddr *>(&address),&length)==0);
    std::mutex mutex; std::condition_variable changed;
    bool entered=false, release=false;
    std::atomic<unsigned> retired{0};
    std::atomic<bool> joined{false};
    amnezia::NativeDNSCallbacks callbacks{};
    callbacks.bind=[&](int64_t,int) {
        std::unique_lock<std::mutex> lock(mutex);
        entered=true; changed.notify_all();
        changed.wait(lock,[&]{return release;});
        return true; // Late success must NOT authorize a post-quiesce connect.
    };
    callbacks.retired=[&](int64_t){retired++;};
    amnezia::NativeDNSState state(callbacks); Capture capture;
    assert(state.policy(true)); state.begin();
    assert(state.prepareScoped("198.19.255.1","127.0.0.1:"+std::to_string(ntohs(address.sin_port)))>0);
    assert(state.attach(capture.fd[0],false));
    auto wire=packet(0x3470,1); assert(state.feed(wire.data(),wire.size())==1);
    {
        std::unique_lock<std::mutex> lock(mutex);
        assert(changed.wait_for(lock,std::chrono::seconds(2),[&]{return entered;}));
    }
    state.quiesce();
    wire=packet(0x3471,28); assert(state.feed(wire.data(),wire.size())==1);
    receive(capture.fd[1],0x3471,0,false);
    std::thread stop([&]{state.stop(); joined=true; changed.notify_all();});
    {
        std::unique_lock<std::mutex> lock(mutex);
        assert(!changed.wait_for(lock,std::chrono::milliseconds(50),[&]{return joined.load();}));
        assert(retired==0 && state.owned() && !state.releasePolicy());
        release=true; changed.notify_all();
    }
    stop.join();
    assert(joined && retired==1 && state.owned());
    assert(state.releasePolicy() && !state.owned());
    pollfd pending{upstream,POLLIN,0};
    assert(poll(&pending,1,50)==0); // No late UDP packet/default resolver fallback.
    ::close(upstream);
}
void testScopedForwarding()
{
    // Real loopback UDP/TCP upstream. The callback admits the SAME pre-connect
    // AF_INET descriptor; Android Network.bindSocket itself needs device acceptance.
    int udp = socket(AF_INET, SOCK_DGRAM, 0), tcp = socket(AF_INET, SOCK_STREAM, 0);
    assert(udp >= 0 && tcp >= 0);
    sockaddr_in address{}; address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(udp, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(udp, reinterpret_cast<sockaddr *>(&address), &length) == 0);
    assert(bind(tcp, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
    assert(listen(tcp, 1) == 0);
    auto answer = [](std::vector<uint8_t> query) {
        assert(query.size() >= 12);
        query[2] |= 0x80; query[3] = 0xa0; query[7] = 1;
        const uint8_t rr[] = {0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,198,51,100,2};
        query.insert(query.end(), std::begin(rr), std::end(rr));
        return query;
    };
    auto ready = [](int fd) { pollfd p{fd, POLLIN, 0}; assert(poll(&p,1,5000)==1); };
    std::thread udpServer([&] {
        ready(udp);
        std::vector<uint8_t> wire(65535);
        sockaddr_in peer{}; socklen_t size=sizeof(peer);
        auto count=recvfrom(udp,wire.data(),wire.size(),0,reinterpret_cast<sockaddr *>(&peer),&size);
        assert(count>=12); wire.resize(count); wire=answer(wire);
        assert(sendto(udp,wire.data(),wire.size(),0,reinterpret_cast<sockaddr *>(&peer),size)==
               static_cast<ssize_t>(wire.size()));
    });
    std::thread tcpServer([&] {
        ready(tcp);
        int fd=accept(tcp,nullptr,nullptr); assert(fd>=0);
        auto readExact = [&](uint8_t *out, size_t size) {
            while(size) { ready(fd); auto n=::read(fd,out,size); assert(n>0); out+=n; size-=n; }
        };
        uint8_t prefix[2]; readExact(prefix,2);
        std::vector<uint8_t> wire((prefix[0]<<8)|prefix[1]);
        assert(wire.size()>=12); readExact(wire.data(),wire.size()); wire=answer(wire);
        put16(prefix,wire.size());
        std::vector<uint8_t> frame(prefix,prefix+2); frame.insert(frame.end(),wire.begin(),wire.end());
        size_t offset=0;
        while(offset<frame.size()) {
            auto n=::write(fd,frame.data()+offset,frame.size()-offset); assert(n>0); offset+=n;
        }
        ::close(fd);
    });
    std::atomic<unsigned> binds{0}, retired{0};
    amnezia::NativeDNSCallbacks callbacks{};
    callbacks.bind = [&](int64_t, int fd) {
        int domain=0; socklen_t size=sizeof(domain);
        assert(getsockopt(fd,SOL_SOCKET,SO_DOMAIN,&domain,&size)==0 && domain==AF_INET);
        sockaddr_storage peer{}; size=sizeof(peer);
        assert(getpeername(fd,reinterpret_cast<sockaddr *>(&peer),&size)<0 && errno==ENOTCONN);
        binds++; return true;
    };
    callbacks.retired = [&](int64_t) { retired++; };
    amnezia::NativeDNSState state(callbacks); Capture capture;
    assert(state.policy(true)); state.begin();
    assert(state.prepareScoped("198.19.255.1","127.0.0.1:"+std::to_string(ntohs(address.sin_port)))>0);
    assert(state.attach(capture.fd[0],false));
    auto wire=packet(0x3460,28); assert(state.feed(wire.data(),wire.size())==1);
    receive(capture.fd[1],0x3460,0,false); assert(binds==0);
    wire=packet(0x3461,1); assert(state.feed(wire.data(),wire.size())==1);
    receive(capture.fd[1],0x3461,0,true);
    TCPPeer peer(state,capture.fd[1]);
    auto response=peer.query(0x3462,1);
    assert(response[7]==1 && (response[3]&0x20)); peer.close();
    udpServer.join(); tcpServer.join();
    assert(binds==2);
    state.stop(); assert(state.releasePolicy() && retired==1);
    ::close(udp); ::close(tcp);
}
void testScopedNoFallback()
{
    std::atomic<unsigned> binds{0}, types{0}, retired{0}, failures{0};
    amnezia::NativeDNSCallbacks callbacks{};
    callbacks.failed = [&](int64_t) { failures++; };
    callbacks.retired = [&](int64_t) { retired++; };
    callbacks.bind = [&](int64_t, int fd) {
        binds++;
        int domain = 0, type = 0;
        socklen_t size = sizeof(int);
        assert(getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &size) == 0 && domain == AF_INET);
        size = sizeof(int);
        assert(getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0);
        types.fetch_or(type == SOCK_STREAM ? 1 : type == SOCK_DGRAM ? 2 : 0);
        sockaddr_storage peer{}; size = sizeof(peer);
        assert(getpeername(fd, reinterpret_cast<sockaddr *>(&peer), &size) < 0 && errno == ENOTCONN);
        return false; // Missing original Network must never become a default connect.
    };
    amnezia::NativeDNSState state(callbacks);
    Capture capture;
    for (const auto &server : {std::string("[fd77::53]:53"), std::string("192.0.2.53:53")}) {
        assert(state.policy(true));
        state.begin();
        assert(state.prepareScoped("198.19.255.1", server) > 0);
        assert(state.attach(capture.fd[0], false));
        auto wire = packet(0x3450, 28);
        assert(state.feed(wire.data(), wire.size()) == 1);
        receive(capture.fd[1], 0x3450, 0, false);
        wire = packet(0x3451, 1);
        assert(state.feed(wire.data(), wire.size()) == 1);
        receive(capture.fd[1], 0x3451, 2, false);
        TCPPeer peer(state, capture.fd[1]);
        const auto nodata = peer.query(0x3452, 28);
        assert(nodata[6] == 0 && nodata[7] == 0 && !(nodata[3] & 0x20));
        const auto refused = peer.query(0x3453, 1, 2);
        assert(refused[6] == 0 && refused[7] == 0 && !(refused[3] & 0x20));
        peer.close();
        if (server[0] == '[') assert(binds == 0); // No privileged IPv6 resolver exception.
        else assert(binds == 2 && types == 3); // Both real UDP4/TCP4 refused before connect.
        state.stop();
        assert(state.releasePolicy() && !state.owned());
    }
    assert(retired == 2 && failures == 0);
}
}
#endif
