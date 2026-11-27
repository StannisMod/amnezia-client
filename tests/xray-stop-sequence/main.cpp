#include "../../client/core/protocols/xrayStopSequence.h"
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

void require(bool condition)
{
    if (!condition) std::abort(); // Assertions remain active in Release builds.
}

int main()
{
    for (unsigned failure = 0; failure < 5; ++failure) {
        XrayStopSequence sequence;
        bool fail = true;
        std::string owner = "owned-dns";
        bool dns = true, worker = true, tun = true, engine = true, protection = true;
        std::vector<unsigned> events;
        const auto step = [&](unsigned phase, bool &resource) {
            events.push_back(phase);
            if (fail && phase == failure) return false;
            resource = false;
            return true;
        };
        const std::array<XrayStopSequence::Operation, 5> operations{{
            [&] { return step(0, dns); }, [&] { return step(1, worker); },
            [&] { return step(2, tun); }, [&] { return step(3, engine); },
            [&] { return step(4, protection); }}};
        require(!sequence.run(operations));
        require(!sequence.complete());
        require(owner == "owned-dns");
        require(events.size() == failure + 1);
        if (failure == 0)
            require(dns && worker && tun && engine && protection);
        if (failure < 4) require(protection);
        fail = false;
        require(sequence.run(operations));
        require(sequence.complete());
        std::vector<unsigned> expected;
        for (unsigned phase = 0; phase <= failure; ++phase) expected.push_back(phase);
        for (unsigned phase = failure; phase < 5; ++phase) expected.push_back(phase);
        require(events == expected);
        owner.clear(); // Caller may release owner only after confirmed cleanup.
        require(!dns && !worker && !tun && !engine && !protection);
        const auto count = events.size();
        require(sequence.run(operations));
        require(events.size() == count); // Successful phases never run twice.
        sequence.reset();
        require(!sequence.complete());
    }
    XrayStopSequence reentrant;
    std::array<XrayStopSequence::Operation, 5> operations;
    for (auto &operation : operations) operation = [] { return true; };
    operations[0] = [&] {
        require(!reentrant.run(operations));
        return true;
    };
    require(reentrant.run(operations));
    std::cout << "PASS: all five failure/retry boundaries; DNS failure retains owner/TUN/engine/protection; "
                 "confirmed teardown ordering; no duplicate phases; reentrancy\n";
}
