#!/usr/bin/env python3
"""Execute the actual production stop body with controlled IPC failure replies.

This is an isolated lifecycle test, not QtRO/installed-Xray runtime acceptance.
"""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
text = (root / "client/core/protocols/xrayProtocol.cpp").read_text()
begin = text.index("void XrayProtocol::stop()\n")
end = text.index("\nErrorCode XrayProtocol::startTun2Socks()", begin)
body = text[begin:end]
fixture = r'''
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <iostream>
#include <cstdlib>
#include "xrayStopSequence.h"
void check(bool value) { if (!value) std::abort(); }
struct Owner : std::string { using std::string::string; bool isEmpty() const { return empty(); } };
struct Call { bool value, delivered = true;
 bool waitForFinished() const { return delivered; } bool returnValue() const { return value; } };
std::vector<std::string> events;
bool restoreOK = false, delivered = true, available = true, running = true;
struct IpcInterfaceReplica {
 Call restoreResolversWithOwner(const Owner &owner) {
  check(owner == "owner"); events.push_back("restore"); return {restoreOK, delivered}; }
 Call deleteTun(const std::string &) { events.push_back("delete-tun"); return {true}; }
 Call xrayStopOwned(long token) { check(token == 42); events.push_back("engine"); return {true}; }
 Call disableKillSwitch() { events.push_back("protection"); return {true}; }
};
template<class T> using QSharedPointer = std::shared_ptr<T>;
struct IpcClient {
 template<class Success, class Failure> static bool withInterface(Success yes, Failure no) {
  if (!available) return no();
  return yes(std::make_shared<IpcInterfaceReplica>());
 }
};
struct Worker {
 void blockSignals(bool) {}
 Call processStopped() { return {!running}; }
 void terminate() { events.push_back("worker"); running = false; }
 void kill() { events.push_back("worker"); running = false; }
 Call waitForFinished(int) { return {!running}; }
 void close() { events.push_back("close-worker"); }
};
struct QObject { static void disconnect(int) {} };
struct QTimer {
 template<class Context, class Callback> static void singleShot(int, Context *, Callback) {}
};
namespace Vpn { enum class ConnectionState { Disconnected }; }
struct Sink { template<class T> Sink &operator<<(const T &) { return *this; } };
Sink qDebug() { return {}; } Sink qWarning() { return {}; }
struct XrayProtocol {
 bool guarded = false, disconnected = false;
 Owner m_dnsOwner = "owner";
 bool m_dnsAttempted = true, m_tunPrepared = true, m_routingApplied = true;
 bool m_destroying = false, m_stopRetryScheduled = false;
 unsigned m_tunGeneration = 1;
 long m_xrayToken = 42;
 int m_dnsFailureConnection = 0;
 std::string tunName = "tun2";
 XrayStopSequence m_stopSequence;
 std::shared_ptr<Worker> m_tun2socksProcess = std::make_shared<Worker>();
 bool guardStop() { bool previous = guarded; guarded = true; return previous; }
 void resetStopGuard() { guarded = false; }
 void setConnectionState(Vpn::ConnectionState) { disconnected = true; }
 void stop();
};
'''
tests = r'''
int main() {
 for (int mode = 0; mode < 3; ++mode) {
  events.clear(); running = true; restoreOK = mode == 1;
  delivered = mode != 1; available = mode != 2;
  XrayProtocol protocol;
  protocol.stop();
  check(protocol.m_dnsOwner == "owner" && protocol.m_dnsAttempted);
  check(protocol.m_tunPrepared && protocol.m_xrayToken == 42);
  check(protocol.m_tun2socksProcess && running && !protocol.disconnected);
  check(protocol.m_stopRetryScheduled && !protocol.guarded);
  check(events == (available ? std::vector<std::string>{"restore"} : std::vector<std::string>{}));
  events.clear(); restoreOK = delivered = available = true;
  protocol.stop();
  check(events == std::vector<std::string>({"restore", "worker", "close-worker",
                                          "delete-tun", "engine", "protection"}));
  check(protocol.m_dnsOwner.empty() && !protocol.m_dnsAttempted);
  check(!protocol.m_tunPrepared && !protocol.m_tun2socksProcess && !protocol.m_xrayToken);
  check(protocol.disconnected && protocol.m_stopSequence.complete());
  const auto count = events.size();
  protocol.stop(); check(events.size() == count);
 }
 std::cout << "PASS: actual XrayProtocol::stop body: refused/lost restore and absent IPC retain "
              "owner/TUN/worker/engine/protection; retry confirms ordered teardown and Disconnected\n";
}
'''
with tempfile.TemporaryDirectory(prefix="xray-stop-") as directory:
    source = Path(directory) / "fixture.cpp"
    source.write_text(fixture + body + tests)
    for platform in ("linux", "windows"):
        binary = Path(directory) / platform
        command = ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
                   "-I" + str(root / "client/core/protocols"), str(source), "-o", str(binary)]
        if platform == "windows":
            command.insert(1, "-DQ_OS_WIN")
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)
        print("PASS: isolated production stop branch", platform, flush=True)
