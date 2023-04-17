import os
import requests

from .. import flask_process, custom_token
from dotenv import load_dotenv


load_dotenv()


class TestSuperAdminPolicy:
    ENDPOINT = str(os.getenv("ENDPOINT"))
    SUPER_ADMIN_ROLE = "super_admin"

    @classmethod
    def setup_class(cls):
        flask_process.set_app_policies(
            ["token_based_policies.authlib_flask_oauth2_policy"], ["super_admin_policy"]
        )
        flask_process.start()

    def setup_method(self):
        flask_process.assert_running()

    def test_token_without_super_admin_role_returns_403(self):
        payload = {"azp": "inuits-policy-based-auth"}
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        assert response.status_code == 403

    def test_request_with_wrong_role_returns_403(self):
        payload = self._get_payload(["regular_user"])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        assert response.status_code == 403

    def test_get_request_with_correct_role_returns_200(self):
        payload = self._get_payload([self.SUPER_ADMIN_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        assert response.status_code == 200

    def test_post_request_with_correct_role_returns_201(self):
        payload = self._get_payload([self.SUPER_ADMIN_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.post(self.ENDPOINT, headers=headers)

        assert response.status_code == 201

    def _get_payload(self, roles):
        return {
            "azp": "inuits-policy-based-auth",
            "resource_access": {"inuits-policy-based-auth": {"roles": roles}},
        }

    @classmethod
    def teardown_class(cls):
        flask_process.stop()
