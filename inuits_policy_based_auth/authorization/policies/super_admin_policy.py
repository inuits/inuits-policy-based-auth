import os

from inuits_policy_based_auth.authorization.base_authorization_policy import (
    BaseAuthorizationPolicy,
)


class SuperAdminPolicy(BaseAuthorizationPolicy):
    """
    An authorization policy that allows a user to do anything if he/she has a super
    admin role.
    """

    super_admin_role: str = os.getenv("SUPER_ADMIN_ROLE", "super_admin")

    def authorize(self, policy_context, user_context, request_context):
        if self.super_admin_role in user_context.roles:
            policy_context.access_verdict = True

        return policy_context
