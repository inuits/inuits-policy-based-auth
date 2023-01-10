from inuits_policy_based_auth.authorization.base_authorization_policy import (
    BaseAuthorizationPolicy,
)


class SuperAdminPolicy(BaseAuthorizationPolicy):
    """
    An authorization policy that allows a user to do anything if he/she has the role 'role_super_admin'.
    """

    def authorize(self, policy_context, user_context, request_context):
        if "role_super_admin" in user_context.roles:
            policy_context.access_verdict = True

        return policy_context
