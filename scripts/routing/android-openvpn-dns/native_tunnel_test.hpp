namespace {
void testNativeDNSEngineCancellationAndCallbackJoin()
{
    std::vector<std::function<void()>> queued;
    std::atomic<unsigned> sent{0};
    auto gate=amnezia::NativeDNSEngine::create(
        [&](std::function<void()> task){queued.push_back(std::move(task));},
        [&](const uint8_t *bytes,int size){assert(size==20 && bytes[0]==0x45);sent++;});
    uint8_t bytes[20]{0x45};
    assert(gate->enqueue(bytes,sizeof(bytes)));bytes[0]=0x60;
    queued.front()();assert(sent==1);queued.clear();
    bytes[0]=0x45;
    assert(gate->enqueue(bytes,sizeof(bytes)));
    gate->close();queued.front()();assert(sent==1);
    assert(!gate->enqueue(bytes,sizeof(bytes)));
    queued.clear();

    std::mutex mutex;std::condition_variable changed;
    bool entered=false,allowReturn=false,closing=false,closed=false;
    unsigned executions=0;
    gate=amnezia::NativeDNSEngine::create(
        [&](std::function<void()> task){queued.push_back(std::move(task));},
        [&](const uint8_t *,int){
            std::unique_lock<std::mutex> lock(mutex);
            executions++;entered=true;changed.notify_all();
            changed.wait(lock,[&]{return allowReturn;});
        });
    assert(gate->enqueue(bytes,sizeof(bytes)));
    auto firstTask=queued.front();
    std::thread execute([firstTask]{firstTask();});
    {
        std::unique_lock<std::mutex> lock(mutex);
        assert(changed.wait_for(lock,std::chrono::seconds(2),[&]{return entered;}));
    }
    bool enqueued=false,quiesced=false;
    std::thread cancel([&]{
        const auto accepted=gate->enqueue(bytes,sizeof(bytes));
        gate->quiesce(); // MUST NOT wait for an executing engine callback.
        {std::lock_guard<std::mutex> lock(mutex);enqueued=accepted;quiesced=true;changed.notify_all();}
    });
    bool cancelledPromptly=false;
    {
        std::unique_lock<std::mutex> lock(mutex);
        cancelledPromptly=changed.wait_for(lock,std::chrono::seconds(2),[&]{return quiesced;});
        if(!cancelledPromptly){allowReturn=true;changed.notify_all();}
    }
    cancel.join();
    if(!cancelledPromptly){execute.join();assert(cancelledPromptly);}
    assert(enqueued && gate->retiring() && !gate->enqueue(bytes,sizeof(bytes)));
    std::thread retire([&]{
        {std::lock_guard<std::mutex> lock(mutex);closing=true;changed.notify_all();}
        gate->close();
        {std::lock_guard<std::mutex> lock(mutex);closed=true;changed.notify_all();}
    });
    {
        std::unique_lock<std::mutex> lock(mutex);
        assert(changed.wait_for(lock,std::chrono::seconds(2),[&]{return closing;}));
        assert(!changed.wait_for(lock,std::chrono::milliseconds(25),[&]{return closed;}));
        allowReturn=true;changed.notify_all();
    }
    execute.join();retire.join();assert(closed);
    queued.back()();assert(executions==1); // Cancelled payload can never revive.
    queued.clear();
}

struct NativeTunnelABIProbe {
    Capture capture;
    std::atomic<int64_t> handle{0};
    std::atomic<unsigned> writes{0}, releases{0}, failures{0};

    static int32_t output(void *host, const uint8_t *bytes, int32_t size)
    {
        auto &s = *static_cast<NativeTunnelABIProbe *>(host);
        return ::write(s.capture.fd[0], bytes, size) == size;
    }
    static int32_t engine(void *host, const uint8_t *bytes, int32_t size)
    {
        auto &s = *static_cast<NativeTunnelABIProbe *>(host);
        s.writes++;
        assert(size >= 40 && bytes[0] == 0x45 && bytes[9] == 17);
        const uint8_t expectedSource[]{10,8,0,2}, expectedTarget[]{10,8,0,1};
        assert(std::memcmp(bytes+12,expectedSource,4)==0);
        assert(std::memcmp(bytes+16,expectedTarget,4)==0);
        assert(bytes[22]==0 && bytes[23]==53);
        std::vector<uint8_t> response(bytes,bytes+size);
        for(unsigned i=0;i<4;i++) std::swap(response[12+i],response[16+i]);
        for(unsigned i=0;i<2;i++) std::swap(response[20+i],response[22+i]);
        response[26]=response[27]=0; // IPv4 UDP checksum is optional.
        response[30]|=0x80;response[31]=0xa0;response[35]=1;
        const uint8_t rr[]{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,198,51,100,2};
        response.insert(response.end(),std::begin(rr),std::end(rr));
        put16(response.data()+2,response.size());put16(response.data()+24,response.size()-20);
        response[10]=response[11]=0;
        unsigned sum=0;
        for(unsigned i=0;i<20;i+=2)sum+=(response[i]<<8)|response[i+1];
        while(sum>>16)sum=(sum&65535)+(sum>>16);
        put16(response.data()+10,(~sum)&65535);
        assert(AmneziaOpenVPNDNSFeedTunnel(s.handle,response.data(),response.size())==1);
        return 1;
    }
    static void failed(void *host,int64_t)
    { static_cast<NativeTunnelABIProbe *>(host)->failures++; }
    static void release(void *host)
    { static_cast<NativeTunnelABIProbe *>(host)->releases++; }
};

void testNativeTunnelCABIWithoutOSNetworkBinding()
{
    testNativeDNSEngineCancellationAndCallbackJoin();
    NativeTunnelABIProbe s;
    const auto policy=AmneziaOpenVPNDNSPolicy(1);assert(policy>0);
    char alias[]="198.19.255.1", source[]="10.8.0.2", upstream[]="10.8.0.1:53";
    char transport[]="plain", empty[]="";
    s.handle=AmneziaOpenVPNDNSStartTunnel(alias,source,upstream,transport,empty,empty,1280,policy,
        &s,NativeTunnelABIProbe::output,NativeTunnelABIProbe::engine,
        NativeTunnelABIProbe::failed,NativeTunnelABIProbe::release);
    assert(s.handle>0);
    auto wire=packet(0x3590,28);
    assert(AmneziaOpenVPNDNSFeed(s.handle,wire.data(),wire.size())==1);
    receive(s.capture.fd[1],0x3590,0,false);assert(s.writes==0);
    wire=packet(0x3591,1);
    assert(AmneziaOpenVPNDNSFeed(s.handle,wire.data(),wire.size())==1);
    receive(s.capture.fd[1],0x3591,0,true);assert(s.writes==1);
    wire=packet(0x3592,1); // An ordinary native peer/port is not captured.
    const auto unchanged=wire;
    assert(AmneziaOpenVPNDNSFeedTunnel(s.handle,wire.data(),wire.size())==0 && wire==unchanged);
    assert(AmneziaOpenVPNDNSReleasePolicy(policy)==0);
    assert(AmneziaOpenVPNDNSStop(s.handle)==1);
    assert(s.releases==1 && s.failures==0);
    assert(AmneziaOpenVPNDNSReleasePolicy(policy)==1);
}
}
