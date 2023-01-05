from inuits_policy_based_auth import BasePolicy, UserAuthData
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
