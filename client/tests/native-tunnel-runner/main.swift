import Foundation

func require(_ value: @autoclosure () -> Bool, _ message: String) {
    if !value() { fatalError(message) }
}

final class Counts {
    let lock = NSLock()
    var starts: [Bool] = []
    var exits: [Bool] = []
    var quits = 0
    var stops = 0
    func change(_ body: (Counts) -> Void) { lock.lock(); body(self); lock.unlock() }
    func read<T>(_ body: (Counts) -> T) -> T { lock.lock(); defer { lock.unlock() }; return body(self) }
}

do {
    let runner = NativeTunnelRunner(), counts = Counts()
    let entered = DispatchSemaphore(value: 0), allowReady = DispatchSemaphore(value: 0)
    let announced = DispatchSemaphore(value: 0), quit = DispatchSemaphore(value: 0)
    let allowExit = DispatchSemaphore(value: 0), stopped = DispatchSemaphore(value: 0)
    runner.start(run: {
        entered.signal()
        require(allowReady.wait(timeout: .now() + 5) == .success, "fixture readiness was not released")
        runner.ready()
        require(quit.wait(timeout: .now() + 5) == .success, "early Stop was not delivered at readiness")
        require(allowExit.wait(timeout: .now() + 5) == .success, "fixture reader exit was not released")
        return 0
    }, quit: { counts.change { $0.quits += 1 }; quit.signal() },
    started: { error in counts.change { $0.starts.append(error != nil) }; announced.signal() },
    exited: { error in counts.change { $0.exits.append(error != nil) } })
    require(entered.wait(timeout: .now() + 5) == .success, "native runner did not enter")
    for _ in 0..<2 {
        runner.stop { counts.change { $0.stops += 1 }; stopped.signal() }
    }
    require(counts.read { $0.quits == 0 && $0.stops == 0 }, "Stop touched an uninitialized native backend")
    allowReady.signal()
    require(announced.wait(timeout: .now() + 5) == .success, "cancelled startup was not completed")
    require(counts.read { $0.starts == [true] && $0.stops == 0 }, "cancelled startup succeeded or Stop skipped reader join")
    allowExit.signal()
    for _ in 0..<2 { require(stopped.wait(timeout: .now() + 5) == .success, "Stop did not join reader exit") }
    require(counts.read { $0.quits == 1 && $0.stops == 2 && $0.exits == [false] }, "duplicate quit or missing lifecycle completion")
    runner.ready()
    require(counts.read { $0.starts.count == 1 }, "late readiness revived a finished run")
}

do {
    let runner = NativeTunnelRunner(), counts = Counts()
    let ready = DispatchSemaphore(value: 0), quit = DispatchSemaphore(value: 0)
    let stopped = DispatchSemaphore(value: 0)
    runner.start(run: {
        runner.ready(); runner.ready()
        require(quit.wait(timeout: .now() + 5) == .success, "ready callback could not request Stop")
        return 0
    }, quit: { counts.change { $0.quits += 1 }; quit.signal() }, started: { error in
        require(error == nil, "normal readiness failed")
        counts.change { $0.starts.append(false) }
        runner.stop { stopped.signal() }
        ready.signal()
    }, exited: { error in require(error == nil, "normal Stop reported backend failure") })
    require(ready.wait(timeout: .now() + 5) == .success, "Stop from readiness callback deadlocked")
    require(stopped.wait(timeout: .now() + 5) == .success, "reader did not stop after ready callback")
    require(counts.read { $0.starts == [false] && $0.quits == 1 }, "readiness was delivered twice")
}

do {
    let runner = NativeTunnelRunner(), counts = Counts()
    let started = DispatchSemaphore(value: 0), exited = DispatchSemaphore(value: 0)
    runner.start(run: { -7 }, quit: { counts.change { $0.quits += 1 } },
        started: { error in counts.change { $0.starts.append(error != nil) }; started.signal() },
        exited: { error in counts.change { $0.exits.append(error != nil) }; exited.signal() })
    require(started.wait(timeout: .now() + 5) == .success && exited.wait(timeout: .now() + 5) == .success,
            "failed native initialization did not finish")
    let stopped = DispatchSemaphore(value: 0)
    runner.stop { stopped.signal() }
    require(stopped.wait(timeout: .now() + 5) == .success, "Stop after failed init hung")
    require(counts.read { $0.starts == [true] && $0.exits == [true] && $0.quits == 0 },
            "failed initialization used unsafe native quit")
}

do {
    let runner = NativeTunnelRunner()
    let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
    let exited = DispatchSemaphore(value: 0), rejected = DispatchSemaphore(value: 0)
    runner.start(run: {
        entered.signal()
        require(release.wait(timeout: .now() + 5) == .success, "fixture release missing")
        return -1
    }, quit: {}, started: { _ in }, exited: { _ in exited.signal() })
    require(entered.wait(timeout: .now() + 5) == .success, "fixture did not enter")
    runner.start(run: { fatalError("duplicate native reader started") }, quit: {},
        started: { error in require(error != nil, "duplicate native startup accepted"); rejected.signal() }, exited: { _ in })
    require(rejected.wait(timeout: .now() + 5) == .success, "duplicate startup not completed")
    release.signal()
    require(exited.wait(timeout: .now() + 5) == .success, "fixture did not exit")
}

print("PASS: native reader readiness, early/duplicate Stop, joined exit, failed init and duplicate startup")
