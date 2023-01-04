from inuits_policy_based_auth.authorization.base_policy import BasePolicy
from werkzeug.exceptions import Forbidden


class SuperAdminPolicy(BasePolicy):
    def authenticate(self, authenticator, context):
        return authenticator.authenticate()

    def authorize(self, user_auth_data, context):
        if not "role_super_admin" in user_auth_data.roles:
            raise Forbidden()
