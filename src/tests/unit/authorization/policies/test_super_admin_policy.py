from inuits_policy_based_auth.authorization.policies.super_admin_policy import (
    SuperAdminPolicy,
)
from inuits_policy_based_auth.contexts import PolicyContext, RequestContext, UserContext
from inuits_policy_based_auth.helpers.tenant import Tenant


class TestSuperAdminPolicy:
    def setup_method(self):
        self.super_admin_policy = SuperAdminPolicy()
        self.policy_context = PolicyContext()
        self.user_context = UserContext()
        self.request_context = RequestContext(None)
        self.user_context.x_tenant = Tenant()

    def test_authorize_allows_access(self):
        self.user_context.x_tenant.roles = ["super_admin"]  # pyright: ignore
        policy_context = self.super_admin_policy.authorize(
            self.policy_context, self.user_context, self.request_context
        )
        assert policy_context.access_verdict == True

    def test_authorize_does_not_determine_access(self):
        self.user_context.x_tenant.roles = ["regular_user"]  # pyright: ignore
        policy_context = self.super_admin_policy.authorize(
            self.policy_context, self.user_context, self.request_context
        )
        assert policy_context.access_verdict is None
