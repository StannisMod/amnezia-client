"""Bounded helper shutdown while draining its status pipe."""


def stop_helper(process, *, graceful=True, timeout=15):
    # Waiting without reading stdout can deadlock: the helper emits periodic
    # status on the same thread that consumes stop/EOF. communicate drains both
    # pipes while delivering stop (or EOF for the command-pipe-loss control).
    command = "stop\n" if graceful and process.poll() is None else None
    output, errors = process.communicate(input=command, timeout=timeout)
    assert process.returncode == 0, "routing helper exited unsuccessfully"
    return output, errors
