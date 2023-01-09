from inuits_policy_based_auth.authorization.base_authorization_policy import (
    BaseAuthorizationPolicy,
)
from werkzeug.exceptions import Forbidden


class SuperAdminPolicy(BaseAuthorizationPolicy):
    """
    An authorization policy that allows a user to do anything if he/she has the role 'role_super_admin'.
    """

    def authorize(self, user_context, request_context):
        if not "role_super_admin" in user_context.roles:
            raise Forbidden()
