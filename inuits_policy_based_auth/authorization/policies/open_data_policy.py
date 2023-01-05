from inuits_policy_based_auth.authentication.user_auth_data import UserAuthData
from inuits_policy_based_auth.authorization.base_policy import BasePolicy
from werkzeug.exceptions import Forbidden


class OpenDataPolicy(BasePolicy):
    """
    A policy that allows every GET-request.
    """

    def authenticate(self, authenticator, context):
        return UserAuthData(auth_object=None)

    def authorize(self, user_auth_data, context):
        request = context.http_request
        if request.method != "GET":
            raise Forbidden()
