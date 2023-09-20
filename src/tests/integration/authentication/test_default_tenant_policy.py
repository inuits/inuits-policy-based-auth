import os
import requests

from .. import flask_process, custom_token, helpers
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
        payload = helpers.get_payload([self.SUPER_ADMIN_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        response_body = response.json()
        assert response.status_code == 200
        assert response_body["x_tenant"]["id"] == "/"
        assert response_body["x_tenant"]["roles"] == [self.SUPER_ADMIN_ROLE]
        assert response_body["x_tenant"]["scopes"] == helpers.get_scopes(
            self.SUPER_ADMIN_ROLE
        )
        assert response_body["x_tenant"]["raw"] == {}

    @classmethod
    def teardown_class(cls):
        flask_process.stop()
