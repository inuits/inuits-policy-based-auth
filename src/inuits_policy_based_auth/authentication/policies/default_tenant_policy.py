import os

from inuits_policy_based_auth import RequestContext
from inuits_policy_based_auth.authentication.base_authentication_policy import (
    BaseAuthenticationPolicy,
)
from inuits_policy_based_auth.contexts import UserContext
from inuits_policy_based_auth.helpers.tenant import Tenant
from storage.storagemanager import StorageManager
from werkzeug.exceptions import Unauthorized


class DefaultTenantPolicy(BaseAuthenticationPolicy):
    """
    An authentication policy that gets or creates (when applicable) a
    tenant, using the details from the configured tenant defining
    header (default 'X-tenant-id').

    Parameters:
    -----------
    tenant_defining_types : list, optional
        List of types that defines a tenant.
    """

    def __init__(self, tenant_defining_types):
        self._tenant_defining_types = tenant_defining_types

    def authenticate(self, user_context: UserContext, request_context: RequestContext):
        """
        Get tenant from tenant defining header and set x_tenant accordingly.

        Parameters:
        -----------
        user_context : UserContext
            The context of the user requesting authentication.
        request_context : RequestContext
            The context of the request.

        Returns:
        --------
        UserContext
            The user context with x_tenant set.

        Raises:
        -------
        Unauthorized
            If the authentication fails.
        """

        if self._tenant_defining_types:
            return user_context
        auth_header = os.getenv("TENANT_DEFINING_HEADER", "X-tenant-id")
        if not (tenant_id := request_context.http_request.headers.get(auth_header)):
            raise Unauthorized(f"{auth_header} header not present")
        storage = StorageManager().get_db_engine()
        tenant = storage.get_item_from_collection_by_id("entities", tenant_id)
        if not tenant:
            if not os.getenv("AUTO_CREATE_TENANTS"):
                raise Unauthorized(f"Tenant with identifier {tenant_id} not found")
            tenant = storage.save_item_to_collection(
                "entities", {"type": "tenant", "identifiers": [tenant_id]}
            )
        user_context.x_tenant = Tenant()
        user_context.x_tenant.id = tenant["_id"]
        user_context.x_tenant.raw = tenant
        return user_context
