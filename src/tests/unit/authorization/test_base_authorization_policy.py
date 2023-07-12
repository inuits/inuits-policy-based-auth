import pytest

from inuits_policy_based_auth import BaseAuthorizationPolicy
from inuits_policy_based_auth.contexts import PolicyContext, RequestContext, UserContext
from inuits_policy_based_auth.exceptions import (
    AuthorizeMethodDidNotReturnObjectOfTypePolicyContextException,
)
from unittest.mock import Mock, patch


class TestBaseAuthorizationPolicy:
    @patch(
        "inuits_policy_based_auth.authorization.base_authorization_policy.BaseAuthorizationPolicy.__abstractmethods__",
        set(),
    )
    def setup_method(self, _):
        self.policy = BaseAuthorizationPolicy()  # type: ignore
        self.spy_policy_authorize = Mock()
        self.policy_context = PolicyContext()
        self.user_context = UserContext()
        self.request_context = RequestContext(None)

        self.policy.authorize = self.spy_policy_authorize

    def test_apply_returns_policy_context(self):
        self.policy.authorize.return_value = self.policy_context

        policy_context = self.policy.apply(
            self.policy_context, self.user_context, self.request_context
        )

        self.policy.authorize.assert_called_once()
        assert policy_context is self.policy_context

    def test_apply_sets_policy_context_access_verdict_to_none_by_default(self):
        self.policy_context.access_verdict = True
        self.policy.authorize.return_value = self.policy_context

        policy_context = self.policy.apply(
            self.policy_context, self.user_context, self.request_context
        )

        self.policy.authorize.assert_called_once()
        assert policy_context.access_verdict == None

    def test_apply_raises_AuthorizeMethodDidNotReturnObjectOfTypePolicyContextException(
        self,
    ):
        with pytest.raises(
            AuthorizeMethodDidNotReturnObjectOfTypePolicyContextException
        ):
            self.policy.apply(
                self.policy_context, self.user_context, self.request_context
            )

        self.policy.authorize.assert_called_once()
