import os
import requests

from .. import flask_process, custom_token
from dotenv import load_dotenv


load_dotenv()


class TestOpenDataPolicy:
    ENDPOINT = str(os.getenv("ENDPOINT"))

    @classmethod
    def setup_class(cls):
        flask_process.set_app_policies(
            ["token_based_policies.authlib_flask_oauth2_policy"], ["open_data_policy"]
        )
        flask_process.start()

    def setup_method(self):
        flask_process.assert_running()

    def test_non_get_request_returns_403(self):
        payload = {"azp": "inuits-policy-based-auth"}
        headers = custom_token.get_authorization_header(payload)

        response = requests.post(self.ENDPOINT, headers=headers)

        assert response.status_code == 403

    def test_get_request_returns_200(self):
        payload = {"azp": "inuits-policy-based-auth"}
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        assert response.status_code == 200

    @classmethod
    def teardown_class(cls):
        flask_process.stop()
