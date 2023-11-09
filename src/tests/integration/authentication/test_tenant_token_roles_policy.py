import os
import requests

from .. import flask_process, custom_token, helpers
from dotenv import load_dotenv


load_dotenv()


class TestTenantTokenRolesPolicy:
    ENDPOINT = str(os.getenv("ENDPOINT"))
    SUPER_ADMIN_ROLE = "super_admin"

    def test_call_without_token_returns_401_when_anonymous_users_not_allowed(self):
        self.__start_flask_process()
        response = requests.get(self.ENDPOINT)
        assert response.status_code == 401

    def test_call_without_token_returns_200_when_anonymous_users_allowed(self):
        self.__start_flask_process(allow_anonymous_users=True)
        response = requests.get(self.ENDPOINT)

        response_body = response.json()
        assert response.status_code == 200
        assert response_body["x_tenant"]["id"] == ""
        assert response_body["x_tenant"]["roles"] == []
        assert response_body["x_tenant"]["scopes"] == []
        assert response_body["x_tenant"]["raw"] == {}

    def test_policy_sets_correct_roles_and_scopes_when_anonymous_users_not_allowed(
        self,
    ):
        self.__start_flask_process(load_oauth2_policy=True)
        payload = helpers.get_payload([self.SUPER_ADMIN_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        response_body = response.json()
        assert response.status_code == 200
        assert response_body["x_tenant"]["id"] == ""
        assert response_body["x_tenant"]["roles"] == [self.SUPER_ADMIN_ROLE]
        assert response_body["x_tenant"]["scopes"] == helpers.get_scopes(
            self.SUPER_ADMIN_ROLE
        )
        assert response_body["x_tenant"]["raw"] == {}

    def __start_flask_process(
        self, allow_anonymous_users=False, load_oauth2_policy=False
    ):
        os.environ["ALLOW_ANONYMOUS_USERS"] = (
            "true" if allow_anonymous_users else "false"
        )
        authentication_policies = [
            "token_based_policies.tenant_token_roles_policy",
        ]
        if load_oauth2_policy:
            authentication_policies.insert(
                0, "token_based_policies.authlib_flask_oauth2_policy"
            )

        flask_process.set_app_policies(authentication_policies, ["open_data_policy"])
        flask_process.start()
        flask_process.assert_running()

    def teardown_method(self):
        flask_process.stop()
