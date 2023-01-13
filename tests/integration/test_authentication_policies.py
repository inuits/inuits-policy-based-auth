import os
import requests

from . import flask_process
from dotenv import load_dotenv


load_dotenv()


class TestAuthenticationPolicies:
    ENDPOINT = str(os.getenv("ENDPOINT"))

    @classmethod
    def setup_class(cls):
        flask_process.start()

    def setup_method(self):
        flask_process.assert_running()

    def test_call_without_token_returns_401(self):
        response = requests.get(self.ENDPOINT)
        assert response.status_code == 401

    @classmethod
    def teardown_class(cls):
        flask_process.stop()
