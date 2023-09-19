import json
import os
import requests

from .. import flask_process, custom_token
from dotenv import load_dotenv


load_dotenv()


class TestScopeBasedPolicy:
    ENDPOINT = str(os.getenv("ENDPOINT"))
    REGULAR_USER_ROLE = "regular_user"

    @classmethod
    def setup_class(cls):
        flask_process.set_app_policies(
            [
                "token_based_policies.authlib_flask_oauth2_policy",
                "token_based_policies.default_tenant_policy",
            ],
            ["scope_based_policy"],
        )
        flask_process.start()

    def setup_method(self):
        flask_process.assert_running()

    def test_request_with_insufficient_scopes_returns_403(self):
        payload = self._get_payload(["datateam"])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        assert response.status_code == 403

    def test_regular_user_with_invalid_scopes_cannot_successfully_do_post_request(self):
        payload = self._get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.post(self.ENDPOINT, headers=headers)

        assert response.status_code == 403

    def test_request_with_sufficient_scopes_returns_200(self):
        payload = self._get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        json_response = response.json()
        assert response.status_code == 200
        assert json_response["x_tenant"]["roles"] == [self.REGULAR_USER_ROLE]
        assert json_response["x_tenant"]["scopes"] == self._get_scopes(
            self.REGULAR_USER_ROLE
        )

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
