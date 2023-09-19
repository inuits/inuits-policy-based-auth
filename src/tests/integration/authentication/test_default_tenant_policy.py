import json
import os
import requests

from .. import flask_process, custom_token
from dotenv import load_dotenv


load_dotenv()


class TestDefaultTenantPolicy:
    ENDPOINT = str(os.getenv("ENDPOINT"))
    SUPER_ADMIN_ROLE = "super_admin"

    @classmethod
    def setup_class(cls):
        flask_process.set_app_policies(
            [
                "token_based_policies.authlib_flask_oauth2_policy",
                "token_based_policies.default_tenant_policy",
            ],
            ["open_data_policy"],
        )
        flask_process.start()

    def setup_method(self):
        flask_process.assert_running()

    def test_policy_defines_default_tenant_with_correct_roles_and_scopes(self):
        payload = self._get_payload([self.SUPER_ADMIN_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        json_response = response.json()
        assert response.status_code == 200
        assert json_response["x_tenant"]["id"] == "/"
        assert json_response["x_tenant"]["roles"] == [self.SUPER_ADMIN_ROLE]
        assert json_response["x_tenant"]["scopes"] == self._get_scopes(
            self.SUPER_ADMIN_ROLE
        )
        assert json_response["x_tenant"]["raw"] == {}

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
