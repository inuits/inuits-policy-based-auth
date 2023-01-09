from inuits_policy_based_auth.authorization.base_authorization_policy import (
    BaseAuthorizationPolicy,
)
from werkzeug.exceptions import Forbidden


class SuperAdminPolicy(BaseAuthorizationPolicy):
    """
    A policy that allows an authenticated user to do anything when he/she has the role 'role_super_admin'.
    """

    def authenticate(self, authenticator, request_context):
        return authenticator.authenticate()

    def authorize(self, user_context, request_context):
        if not "role_super_admin" in user_context.roles:
            raise Forbidden()
