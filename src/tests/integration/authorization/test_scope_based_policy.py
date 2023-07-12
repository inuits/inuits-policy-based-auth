import os
import requests

from .. import flask_process, custom_token
from dotenv import load_dotenv


load_dotenv()


class TestScopeBasedPolicy:
    ENDPOINT = str(os.getenv("ENDPOINT"))

    @classmethod
    def setup_class(cls):
        flask_process.set_app_policies(
            ["token_based_policies.authlib_flask_oauth2_policy"], ["scope_based_policy"]
        )
        flask_process.start()

    def setup_method(self):
        flask_process.assert_running()

    def test_request_with_insufficient_scopes_returns_403(self):
        payload = self._get_payload(["datateam"])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        assert response.status_code == 403

    def test_request_with_sufficient_scopes_returns_200(self):
        payload = self._get_payload(["regular_user"])
        headers = custom_token.get_authorization_header(payload)

        response = requests.get(self.ENDPOINT, headers=headers)

        assert response.status_code == 200

    def _get_payload(self, roles):
        return {
            "azp": "inuits-policy-based-auth",
            "resource_access": {"inuits-policy-based-auth": {"roles": roles}},
        }

    @classmethod
    def teardown_class(cls):
        flask_process.stop()
