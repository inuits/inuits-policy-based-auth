import json

from inuits_policy_based_auth import BaseAuthenticationPolicy
from inuits_policy_based_auth.contexts import UserContext
from werkzeug.exceptions import Unauthorized


class TenantTokenRolesPolicy(BaseAuthenticationPolicy):
    """
    An authentication policy that defines the roles and scope from the token
    for the x-tenant.

    Parameters:
    -----------
    token_schema : dict
        Dict containing mappings between property <-> path.to.that.property.in.token.
    role_scope_mapping_filepath : str, optional
        Path to a JSON file containing a mapping of scopes to their corresponding roles.
    allow_anonymous_users : bool, optional
        A bool about whether anonymous users are allowed to do requests.
    """

    def __init__(
        self,
        token_schema: dict,
        role_scope_mapping_filepath=None,
        allow_anonymous_users=False,
    ):
        self._token_schema = token_schema
        self._role_scope_mapping = self.__load_role_scope_mapping(
            role_scope_mapping_filepath
        )
        self._allow_anonymous_users = allow_anonymous_users

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
            user_context.x_tenant.roles = flattened_token.get(
                self._token_schema["roles"], []
            )
            if not self._role_scope_mapping:
                return user_context
            for role in user_context.x_tenant.roles:
                try:
                    user_context.x_tenant.scopes.extend(self._role_scope_mapping[role])
                except KeyError:
                    continue
            return user_context
        except Exception:
            if self._allow_anonymous_users:
                return user_context
            else:
                raise Unauthorized()

    def __load_role_scope_mapping(self, file):
        try:
            with open(file, "r") as role_scope_mapping:
                return json.load(role_scope_mapping)
        except Exception:
            pass
