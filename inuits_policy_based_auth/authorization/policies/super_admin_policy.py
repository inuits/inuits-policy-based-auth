from inuits_policy_based_auth.authorization.base_policy import BasePolicy
from werkzeug.exceptions import Forbidden


class SuperAdminPolicy(BasePolicy):
    """
    A policy that allows an authenticated user to do anything when he/she has the role 'role_super_admin'.
    """

    def authenticate(self, authenticator, request_context):
        return authenticator.authenticate()

    def authorize(self, user_auth_data, request_context):
        if not "role_super_admin" in user_auth_data.roles:
            raise Forbidden()
