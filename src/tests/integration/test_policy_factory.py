import json
import os
import pytest
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
            [
                "token_based_policies.authlib_flask_oauth2_policy",
                "token_based_policies.default_tenant_policy",
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

    def test_user_context_can_be_modified_in_authorization_policies(self):
        payload = self._get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.put(self.ENDPOINT, headers=headers)
        json_response = response.json()
        assert response.status_code == 200
        assert json_response["bag"] == {}
        assert json_response["access_restrictions"]["filters"] == None

        response = requests.get(self.ENDPOINT, headers=headers)
        json_response = response.json()
        assert response.status_code == 200
        assert json_response["bag"] == {"test": "test"}
        assert json_response["access_restrictions"]["filters"] == {
            "relations.hasTenant": "/"
        }

    def test_authenticate_on_generic_endpoint_is_not_called_when_goes_through_concrete_endpoint_that_already_authenticated(
        self,
    ):
        payload = self._get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)
        json_response = response.json()
        assert response.status_code == 200
        assert json_response["number_of_authenticate_calls"] == 0
        assert json_response["number_of_apply_policies_calls"] == 1

        response = requests.put(self.ENDPOINT, headers=headers)
        json_response = response.json()
        assert response.status_code == 200
        assert json_response["number_of_authenticate_calls"] == 1
        assert json_response["number_of_apply_policies_calls"] == 0

    def test_request_without_token_returns_401_after_a_successful_request_with_token(
        self,
    ):
        payload = self._get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)
        assert response.status_code == 200

        response = requests.put(self.ENDPOINT)
        assert response.status_code == 401

    def test_user_context_is_cleared_correctly_for_single_user(self):
        payload = self._get_payload([self.REGULAR_USER_ROLE])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)
        json_response = response.json()
        assert response.status_code == 200
        assert json_response["bag"] == {"test": "test"}
        assert json_response["access_restrictions"]["filters"] == {
            "relations.hasTenant": "/"
        }

        response = requests.put(self.ENDPOINT, headers=headers)
        json_response = response.json()
        assert response.status_code == 200
        assert json_response["bag"] == {}
        assert json_response["access_restrictions"]["filters"] == None

    def test_user_context_of_multiple_users_do_not_interfere_with_each_other(self):
        pytest.fail("Not implemented yet.")

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
