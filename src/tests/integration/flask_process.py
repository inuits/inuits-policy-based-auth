import json
import os
import pytest

from subprocess import Popen, DEVNULL
from time import sleep


_flask_process: Popen[bytes]
_sleep_delay = 1


def set_app_policies(authentication: list[str], authorization: list[str]):
    _overwrite_configuration_file(authentication, authorization)


def start():
    global _flask_process
    _flask_process = Popen(["flask", "run"], stdout=DEVNULL, stderr=DEVNULL)
    sleep(_sleep_delay)


def assert_running():
    if _flask_process.poll() != None:
        pytest.fail("flask_process is not running.")


def stop():
    _overwrite_configuration_file()
    _flask_process.kill()
    sleep(_sleep_delay)
    assert _flask_process.poll() != None


def _overwrite_configuration_file(
    authentication: list[str] = [], authorization: list[str] = []
):
    with open(str(os.getenv("TEST_API_CONFIGURATION")), "r+") as configuration_file:
        configuration = json.load(configuration_file)

        for app in ["test_api", "test_api_backup"]:
            if authentication and authorization:
                configuration[app]["policies"]["authentication"].extend(authentication)
                configuration[app]["policies"]["authorization"].extend(authorization)
            else:
                configuration[app]["policies"]["authentication"] = []
                configuration[app]["policies"]["authorization"] = []

        configuration_file.seek(0)
        configuration_file.write(json.dumps(configuration, indent=2))
        configuration_file.truncate()
