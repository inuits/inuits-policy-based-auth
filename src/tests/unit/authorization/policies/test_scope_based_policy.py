from inuits_policy_based_auth.authorization.policies.scope_based_policy import (
    ScopeBasedPolicy,
)
from inuits_policy_based_auth.contexts import PolicyContext, RequestContext, UserContext
from inuits_policy_based_auth.helpers.tenant import Tenant


class TestScopeBasedPolicy:
    def setup_method(self):
        self.scope_based_policy = ScopeBasedPolicy()
        self.policy_context = PolicyContext()
        self.user_context = UserContext()
        self.user_context.x_tenant = Tenant()

    def test_authorize_allows_access(self):
        self.user_context.x_tenant.scopes = ["read"]  # pyright: ignore
        request_context = RequestContext(None, ["create", "read"])

        policy_context = self.scope_based_policy.authorize(
            self.policy_context, self.user_context, request_context
        )

        assert policy_context.access_verdict == True

    def test_authorize_does_not_determine_access(self):
        self.user_context.x_tenant.scopes = ["update"]  # pyright: ignore
        request_context = RequestContext(None, ["create", "read"])

        policy_context = self.scope_based_policy.authorize(
            self.policy_context, self.user_context, request_context
        )

        assert policy_context.access_verdict is None
