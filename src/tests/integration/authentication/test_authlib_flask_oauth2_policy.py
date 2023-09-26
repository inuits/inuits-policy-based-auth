import os
import requests

from .. import flask_process, custom_token
from dotenv import load_dotenv


load_dotenv()


class TestAuthlibFlaskOauth2Policy:
    ENDPOINT = str(os.getenv("ENDPOINT"))

    def test_call_without_token_returns_401_when_anonymous_users_not_allowed(self):
        self.__start_flask_process()
        response = requests.get(self.ENDPOINT)
        assert response.status_code == 401

    def test_call_with_invalid_token_returns_401_when_anonymous_users_not_allowed(self):
        self.__start_flask_process()
        headers = custom_token.get_authorization_header({})
        response = requests.get(self.ENDPOINT, headers=headers)
        assert response.status_code == 401

    def test_call_with_valid_token_returns_200_when_anonymous_users_not_allowed(self):
        self.__start_flask_process()
        payload = {"azp": "inuits-policy-based-auth"}
        headers = custom_token.get_authorization_header(payload)
        response = requests.get(self.ENDPOINT, headers=headers)
        assert response.status_code == 200

    def test_call_without_token_returns_200_when_anonymous_users_allowed(self):
        self.__start_flask_process(allow_anonymous_users=True)
        response = requests.get(self.ENDPOINT)
        assert response.status_code == 200

    def test_call_with_invalid_token_returns_401_when_anonymous_users_allowed(self):
        self.__start_flask_process(allow_anonymous_users=True)
        headers = custom_token.get_authorization_header({})
        response = requests.get(self.ENDPOINT, headers=headers)
        assert response.status_code == 401

    def test_call_with_valid_token_returns_200_when_anonymous_users_allowed(self):
        self.__start_flask_process(allow_anonymous_users=True)
        payload = {"azp": "inuits-policy-based-auth"}
        headers = custom_token.get_authorization_header(payload)
        response = requests.get(self.ENDPOINT, headers=headers)
        assert response.status_code == 200

    def __start_flask_process(self, allow_anonymous_users=False):
        os.environ["ALLOW_ANONYMOUS_USERS"] = (
            "true" if allow_anonymous_users else "false"
        )
        flask_process.set_app_policies(
            ["token_based_policies.authlib_flask_oauth2_policy"], ["open_data_policy"]
        )
        flask_process.start()
        flask_process.assert_running()

    def teardown_method(self):
        flask_process.stop()
