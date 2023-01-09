from inuits_policy_based_auth.authorization.base_policy import BasePolicy
from inuits_policy_based_auth.user_auth_data import UserAuthData
from werkzeug.exceptions import Forbidden


class OpenDataPolicy(BasePolicy):
    """
    A policy that allows every GET-request.
    """

    def authenticate(self, authenticator, request_context):
        return UserAuthData(auth_object=None)

    def authorize(self, user_auth_data, request_context):
        request = request_context.http_request
        if request.method != "GET":
            raise Forbidden()
