import os
import requests

from .. import flask_process, custom_token, helpers
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
                "token_based_policies.tenant_token_roles_policy",
            ],
            ["scope_based_policy"],
        )
        flask_process.start()

    def setup_method(self):
        flask_process.assert_running()

    def test_request_with_insufficient_scopes_returns_403(self):
        payload = helpers.get_payload(["datateam"])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        assert response.status_code == 403

    def test_regular_user_with_invalid_scopes_cannot_successfully_do_post_request(self):
        payload = helpers.get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.post(self.ENDPOINT, headers=headers)

        assert response.status_code == 403

    def test_request_with_sufficient_scopes_returns_200(self):
        payload = helpers.get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        response_body = response.json()
        assert response.status_code == 200
        assert response_body["x_tenant"]["roles"] == [self.REGULAR_USER_ROLE]
        assert response_body["x_tenant"]["scopes"] == helpers.get_scopes(
            self.REGULAR_USER_ROLE
        )

    @classmethod
    def teardown_class(cls):
        flask_process.stop()
