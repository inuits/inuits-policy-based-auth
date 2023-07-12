from inuits_policy_based_auth.authorization.policies.super_admin_policy import (
    SuperAdminPolicy,
)
from inuits_policy_based_auth.contexts import PolicyContext, RequestContext, UserContext


class TestSuperAdminPolicy:
    def setup_method(self):
        self.super_admin_policy = SuperAdminPolicy()
        self.policy_context = PolicyContext()
        self.user_context = UserContext()
        self.request_context = RequestContext(None)

    def test_authorize_allows_access(self):
        self.user_context.roles = ["super_admin"]
        policy_context = self.super_admin_policy.authorize(
            self.policy_context, self.user_context, self.request_context
        )
        assert policy_context.access_verdict == True

    def test_authorize_does_not_determine_access(self):
        self.user_context.roles = ["regular_user"]
        policy_context = self.super_admin_policy.authorize(
            self.policy_context, self.user_context, self.request_context
        )
        assert policy_context.access_verdict == None
