import pytest

from os import environ
from subprocess import Popen, DEVNULL
from time import sleep


class TestIntegration:
    @classmethod
    def setup_class(cls):
        env = environ.copy()
        env["FLASK_APP"] = "tests/integration/test_api/app.py"
        cls.flask_process = Popen(
            ["flask", "run", "--host", "localhost", "--port", "5000"],
            env=env,
            stdout=DEVNULL,
            stderr=DEVNULL,
        )
        sleep(0.2)

    def setup_method(self):
        if self.flask_process.poll() != None:
            pytest.fail(f"flask_process could not start.")

    @classmethod
    def teardown_class(cls):
        cls.flask_process.kill()
        sleep(0.2)
        assert cls.flask_process.poll() != None
