import os
import requests

from . import flask_process, custom_token, helpers
from dotenv import load_dotenv


load_dotenv()


class TestPolicyFactory:
    ENDPOINT = str(os.getenv("ENDPOINT"))
    SUPER_ADMIN_ROLE = "super_admin"
    REGULAR_USER_ROLE = "regular_user"

    @classmethod
    def setup_class(cls):
        flask_process.set_app_policies(
            [
                "token_based_policies.authlib_flask_oauth2_policy",
                "token_based_policies.tenant_token_roles_policy",
            ],
            ["super_admin_policy", "open_data_policy", "scope_based_policy"],
        )
        flask_process.start()

    def setup_method(self):
        flask_process.assert_running()

    def test_single_request_without_token_returns_401(self):
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

    def test_request_without_token_returns_401_after_a_successful_request_with_token(
        self,
    ):
        payload = helpers.get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)
        assert response.status_code == 200

        response = requests.put(self.ENDPOINT)
        assert response.status_code == 401

    def test_user_context_can_be_modified_in_authorization_policies(self):
        payload = helpers.get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.put(self.ENDPOINT, headers=headers)
        response_body = response.json()
        assert response.status_code == 200
        assert response_body["bag"] == {}
        assert response_body["access_restrictions"]["filters"] is None

        response = requests.get(self.ENDPOINT, headers=headers)
        response_body = response.json()
        assert response.status_code == 200
        assert response_body["bag"] == {"test": "test"}
        assert response_body["access_restrictions"]["filters"] == {
            "relations.hasTenant": ""
        }

    def test_user_context_is_cleared_correctly(self):
        payload = helpers.get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)
        response_body = response.json()
        assert response.status_code == 200
        assert response_body["bag"] == {"test": "test"}
        assert response_body["access_restrictions"]["filters"] == {
            "relations.hasTenant": ""
        }

        response = requests.put(self.ENDPOINT, headers=headers)
        response_body = response.json()
        assert response.status_code == 200
        assert response_body["bag"] == {}
        assert response_body["access_restrictions"]["filters"] is None

    @classmethod
    def teardown_class(cls):
        flask_process.stop()
