"""
utils/shutdown.py — make shutdown immune to a collector that won't stop.

Never call a collector's stop() on a thread you need back. Run it on a daemon
worker with a deadline; if it blows the deadline we abandon it and carry on.
Because the worker is a daemon, it cannot keep the interpreter alive.
"""

import os
import signal
import sys
import threading
import time

_SENTINEL = object()


def call_with_result(fn, timeout: float = 5.0, label: str = "task", *args, **kwargs):
    """Run fn(*args) on a daemon thread with a deadline.

    Returns (ok, value, error):
        (True,  value, None)      finished in time
        (False, None,  "timeout") still running, abandoned
        (False, None,  exception) raised
    """
    box = {"value": _SENTINEL, "error": None}

    def runner():
        try:
            box["value"] = fn(*args, **kwargs)
        except Exception as e:
            box["error"] = e

    t = threading.Thread(target=runner, name=f"call-{label}", daemon=True)
    t.start()
    t.join(timeout)

    if t.is_alive():
        print(f"[shutdown] {label} still running after {timeout}s — abandoning it")
        return False, None, "timeout"
    if box["error"] is not None:
        print(f"[shutdown] {label} raised: {box['error']}")
        return False, None, box["error"]
    return True, (None if box["value"] is _SENTINEL else box["value"]), None


def call_with_timeout(fn, timeout: float = 5.0, label: str = "task") -> bool:
    """Fire-and-forget variant. True only if fn() returned cleanly in time."""
    ok, _, _ = call_with_result(fn, timeout, label)
    return ok


def force_exit_if_stuck(grace: float = 3.0, code: int = 0) -> None:
    """Last resort. Non-daemon threads still alive after `grace` seconds mean
    the interpreter will never exit on its own, so exit hard.

    os._exit skips atexit handlers and buffer flushing — call this only after
    the dispatcher has been flushed, and never before stopping anything you
    actually care about stopping.
    """
    def lingering():
        # The main thread is excluded: stop() has already cleared the flag that
        # wait() loops on, so it is on its way out. Including it would make
        # every signal-driven shutdown hard-exit, since this runs on a worker.
        return [t for t in threading.enumerate()
                if t is not threading.current_thread()
                and t is not threading.main_thread()
                and t.is_alive() and not t.daemon]

    deadline = time.time() + grace
    while time.time() < deadline:
        if not lingering():
            return
        time.sleep(0.2)

    names = [t.name for t in lingering()]
    if not names:
        return
    print(f"[shutdown] non-daemon threads still alive {names} — forcing exit")
    sys.stdout.flush()          # os._exit would discard anything buffered
    sys.stderr.flush()
    os._exit(code)


def install_signal_handlers(stop_fn, force_code: int = 1) -> None:
    """Route SIGINT and SIGTERM to stop_fn. A second signal exits immediately,
    so an operator (or systemd) is never stuck waiting on a wedged collector.

    Must be called from the main thread.
    """
    state = {"tripped": False}

    def handler(signum, _frame):
        name = signal.Signals(signum).name
        if state["tripped"]:
            print(f"\n[shutdown] second {name} — forcing exit")
            sys.stdout.flush()
            os._exit(force_code)
        state["tripped"] = True
        print(f"\n[shutdown] {name} received, shutting down (signal again to force)")
        # run the shutdown off the signal handler so the handler returns at once
        threading.Thread(target=stop_fn, name="shutdown", daemon=True).start()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError, AttributeError) as e:
            print(f"[shutdown] could not install handler for {sig}: {e}")