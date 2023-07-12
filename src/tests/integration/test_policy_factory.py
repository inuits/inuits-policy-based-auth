import json
import os
import requests

from . import flask_process, custom_token
from dotenv import load_dotenv


load_dotenv()


class TestPolicyFactory:
    ENDPOINT = str(os.getenv("ENDPOINT"))
    SUPER_ADMIN_ROLE = "super_admin"
    REGULAR_USER_ROLE = "regular_user"

    @classmethod
    def setup_class(cls):
        flask_process.set_app_policies(
            ["token_based_policies.authlib_flask_oauth2_policy"],
            ["super_admin_policy", "scope_based_policy", "open_data_policy"],
        )
        flask_process.start()

    def setup_method(self):
        flask_process.assert_running()

    def test_request_without_token_returns_401(self):
        response = requests.put(self.ENDPOINT)
        assert response.status_code == 401

    def test_request_with_wrong_token_payload_structure_returns_403(self):
        payload = {
            "azp": "inuits-policy-based-auth",
            "inuits-policy-based-auth": {"roles": [self.SUPER_ADMIN_ROLE]},
        }
        headers = custom_token.get_authorization_header(payload)

        response = requests.post(self.ENDPOINT, headers=headers)

        assert response.status_code == 403

    def test_request_with_wrong_token_azp_returns_403(self):
        payload = {
            "azp": "inuits-policy-based-auth",
            "resource_access": {
                "policy-based-auth": {"roles": [self.SUPER_ADMIN_ROLE]}
            },
        }
        headers = custom_token.get_authorization_header(payload)

        response = requests.post(self.ENDPOINT, headers=headers)

        assert response.status_code == 403

    def test_request_with_token_returns_200(self):
        payload = self._get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.put(self.ENDPOINT, headers=headers)

        assert response.status_code == 200

    def test_super_admin_gets_correct_user_context(self):
        payload = self._get_payload([self.SUPER_ADMIN_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        assert response.status_code == 200
        assert response.json()["roles"] == [self.SUPER_ADMIN_ROLE]

    def test_regular_user_with_invalid_scopes_cannot_successfully_do_post_request(self):
        payload = self._get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.post(self.ENDPOINT, headers=headers)

        assert response.status_code == 403

    def test_regular_user_can_successfully_do_get_request(self):
        payload = self._get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        json_response = response.json()
        assert response.status_code == 200
        assert json_response["roles"] == [self.REGULAR_USER_ROLE]
        assert json_response["scopes"] == self._get_scopes(self.REGULAR_USER_ROLE)

    def _get_payload(self, roles):
        return {
            "azp": "inuits-policy-based-auth",
            "resource_access": {"inuits-policy-based-auth": {"roles": roles}},
        }

    def _get_scopes(self, role):
        with open(str(os.getenv("TEST_API_SCOPES")), "r") as scopes_file:
            return json.load(scopes_file)[role]

    @classmethod
    def teardown_class(cls):
        flask_process.stop()
