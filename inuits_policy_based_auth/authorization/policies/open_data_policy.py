from inuits_policy_based_auth.authorization.base_authorization_policy import (
    BaseAuthorizationPolicy,
)


class OpenDataPolicy(BaseAuthorizationPolicy):
    """
    An authorization policy that allows every GET-request.
    """

    def authorize(self, policy_context, user_context, request_context):
        request = request_context.http_request
        if request.method == "GET":
            policy_context.access_verdict = True

        return policy_context
