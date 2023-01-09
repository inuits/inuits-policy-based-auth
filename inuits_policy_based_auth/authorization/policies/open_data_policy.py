from inuits_policy_based_auth.authorization.base_policy import BasePolicy
from inuits_policy_based_auth.contexts.user_context import UserContext
from werkzeug.exceptions import Forbidden


class OpenDataPolicy(BasePolicy):
    """
    A policy that allows every GET-request.
    """

    def authenticate(self, authenticator, request_context):
        return UserContext(auth_object=None)

    def authorize(self, user_context, request_context):
        request = request_context.http_request
        if request.method != "GET":
            raise Forbidden()
