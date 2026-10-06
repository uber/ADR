"""POSIX lifetime guard for review CLIs; no prompts or credentials are inspected."""

import os
import selectors
import signal
import subprocess
import time


def supervise(arguments, lifetime_fd, seconds):
    if os.name == "nt" or not arguments or not 0 < seconds <= 3600:
        return 125
    # The caller must have created this supervisor as a new session leader.
    # Refuse to signal a group that might contain the person's shell.
    if os.getpgrp() != os.getpid():
        return 125
    stopping = False

    def stop(_signal, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    selector = selectors.DefaultSelector()
    child = None
    try:
        os.fstat(lifetime_fd)
        selector.register(lifetime_fd, selectors.EVENT_READ)
        # close_fds prevents the CLI from retaining the parent's lifetime pipe.
        # stdin/stdout/stderr pass straight through, without logging or copying.
        child = subprocess.Popen(arguments, close_fds=True)
        deadline = time.monotonic() + seconds
        while child.poll() is None and not stopping:
            if time.monotonic() >= deadline:
                break
            for _key, _event in selector.select(timeout=0.1):
                if os.read(lifetime_fd, 1) == b"":
                    stopping = True
        if child.poll() is not None:
            return child.returncode
        os.killpg(os.getpgrp(), signal.SIGTERM)
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgrp(), signal.SIGKILL)
        return 143
    finally:
        selector.close()
        os.close(lifetime_fd)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=1)
