import json

from inuits_policy_based_auth.authentication.base_authentication_policy import (
    BaseAuthenticationPolicy,
)
from inuits_policy_based_auth.contexts import UserContext
from inuits_policy_based_auth.helpers.tenant import Tenant
from werkzeug.exceptions import Unauthorized


class DefaultTenantPolicy(BaseAuthenticationPolicy):
    """
    An authentication policy that defines a default x-tenant and includes the
    roles and scope from the token in it.

    Parameters:
    -----------
    role_scope_mapping_filepath : str, optional
        Path to a JSON file containing a mapping of scopes to their corresponding roles.
    """

    def __init__(self, role_scope_mapping_filepath=None):
        self._role_scope_mapping = self.__load_role_scope_mapping(
            role_scope_mapping_filepath
        )

    def authenticate(self, user_context: UserContext, _):
        """
        Obtain the user roles and scopes from the token and store
        them in the default x-tenant.

        Parameters:
        -----------
        user_context : UserContext
            The context of the user requesting authentication.
        request_context : RequestContext
            The context of the request.

        Returns:
        --------
        UserContext
            The user context with the authenticated user details added.

        Raises:
        -------
        Unauthorized
            If the authentication fails.
        """

        try:
            token = user_context.auth_objects["token"]
            flattened_token = user_context.flatten_auth_object(token)
            user_context.x_tenant = Tenant()

            user_context.x_tenant.id = "/"
            user_context.x_tenant.roles = flattened_token.get(
                f"resource_access.{token['azp']}.roles", []
            )
            if self._role_scope_mapping:
                for role in user_context.x_tenant.roles:
                    try:
                        user_context.x_tenant.scopes.extend(
                            self._role_scope_mapping[role]
                        )
                    except KeyError:
                        continue

            return user_context
        except Exception:
            raise Unauthorized()

    def __load_role_scope_mapping(self, file):
        try:
            with open(file, "r") as role_scope_mapping:
                return json.load(role_scope_mapping)
        except Exception:
            pass
