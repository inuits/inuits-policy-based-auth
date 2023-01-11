from .dummies import FakeHttpRequest
from inuits_policy_based_auth.authorization.policies.open_data_policy import (
    OpenDataPolicy,
)
from inuits_policy_based_auth.contexts import PolicyContext, RequestContext, UserContext


class TestOpenDataPolicy:
    def setup_method(self):
        self.fake_http_request = FakeHttpRequest()
        self.open_data_policy = OpenDataPolicy()
        self.policy_context = PolicyContext()
        self.user_context = UserContext()
        self.request_context = RequestContext(self.fake_http_request)

    def test_authorize_allows_access(self):
        self.fake_http_request._request_type = "GET"
        policy_context = self.open_data_policy.authorize(
            self.policy_context, self.user_context, self.request_context
        )
        assert policy_context.access_verdict == True

    def test_authorize_does_not_determine_access(self):
        self.fake_http_request._request_type = "POST"
        policy_context = self.open_data_policy.authorize(
            self.policy_context, self.user_context, self.request_context
        )
        assert policy_context.access_verdict == None
