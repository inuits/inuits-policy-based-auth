from inuits_policy_based_auth.authorization.policies.scope_based_policy import (
    ScopeBasedPolicy,
)
from inuits_policy_based_auth.contexts import PolicyContext, RequestContext, UserContext


class TestScopeBasedPolicy:
    def setup_method(self):
        self.scope_based_policy = ScopeBasedPolicy()
        self.policy_context = PolicyContext()
        self.user_context = UserContext()

    def test_authorize_allows_access(self):
        self.user_context.scopes = ["read"]
        request_context = RequestContext(None, ["create", "read"])

        policy_context = self.scope_based_policy.authorize(
            self.policy_context, self.user_context, request_context
        )

        assert policy_context.access_verdict == True

    def test_authorize_does_not_determine_access(self):
        self.user_context.scopes = ["update"]
        request_context = RequestContext(None, ["create", "read"])

        policy_context = self.scope_based_policy.authorize(
            self.policy_context, self.user_context, request_context
        )

        assert policy_context.access_verdict == None
