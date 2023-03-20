from inuits_policy_based_auth.authorization.base_authorization_policy import (
    BaseAuthorizationPolicy,
)


class ScopeBasedPolicy(BaseAuthorizationPolicy):
    """
    An authorization policy that allows access if you have the correct scopes.
    """

    def authorize(self, policy_context, user_context, request_context):
        for resource_scope in request_context.resource_scopes:
            if resource_scope in user_context.scopes:
                policy_context.access_verdict = True

        return policy_context
