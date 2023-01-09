from inuits_policy_based_auth.authorization.base_authorization_policy import (
    BaseAuthorizationPolicy,
)
from werkzeug.exceptions import Forbidden


class OpenDataPolicy(BaseAuthorizationPolicy):
    """
    An authorization policy that allows every GET-request.
    """

    def authorize(self, user_context, request_context):
        request = request_context.http_request
        if request.method != "GET":
            raise Forbidden()
