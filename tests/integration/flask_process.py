import pytest

from subprocess import Popen, DEVNULL
from time import sleep


_flask_process: Popen[bytes]
_sleep_delay = .5


def start():
    global _flask_process
    _flask_process = Popen(["flask", "run"], stdout=DEVNULL, stderr=DEVNULL)
    sleep(_sleep_delay)


def assert_running():
    if _flask_process.poll() != None:
        pytest.fail(f"flask_process is not running.")


def stop():
    _flask_process.kill()
    sleep(_sleep_delay)
    assert _flask_process.poll() != None
