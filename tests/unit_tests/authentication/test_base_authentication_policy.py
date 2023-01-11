import pytest

from inuits_policy_based_auth import BaseAuthenticationPolicy
from inuits_policy_based_auth.contexts import UserContext
from inuits_policy_based_auth.exceptions import (
    AuthenticateMethodDidNotReturnObjectOfTypeUserContextException,
)
from unittest.mock import Mock, patch


class TestBaseAuthenticationPolicy:
    @patch(
        "inuits_policy_based_auth.authentication.base_authentication_policy.BaseAuthenticationPolicy.__abstractmethods__",
        set(),
    )
    def setup_method(self, _):
        self.policy = BaseAuthenticationPolicy()  # type: ignore
        self.spy_policy_authenticate = Mock()
        self.user_context = UserContext()

        self.policy.authenticate = self.spy_policy_authenticate

    def test_apply_returns_user_context(self):
        self.policy.authenticate.return_value = self.user_context

        user_context = self.policy.apply(self.user_context)

        self.policy.authenticate.assert_called_once()
        assert user_context is self.user_context

    def test_apply_raises_AuthenticateMethodDidNotReturnObjectOfTypeUserContextException(
        self,
    ):
        with pytest.raises(
            AuthenticateMethodDidNotReturnObjectOfTypeUserContextException
        ):
            self.policy.apply(self.user_context)

        self.policy.authenticate.assert_called_once()
