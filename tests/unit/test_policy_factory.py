import pytest

from inuits_policy_based_auth import (
    PolicyFactory,
    BaseAuthenticationPolicy,
    BaseAuthorizationPolicy,
)
from inuits_policy_based_auth.contexts import PolicyContext, RequestContext, UserContext
from inuits_policy_based_auth.exceptions import (
    NoUserContextException,
    NoAuthenticationPoliciesToApplyException,
    NoAuthorizationPoliciesToApplyException,
)
from unittest.mock import Mock, patch
from werkzeug.exceptions import Forbidden


class TestPolicyFactory:
    def setup_method(self):
        self.policy_factory = PolicyFactory(None)
        self.policy_context = PolicyContext()
        self.request_context = RequestContext(None)
        self.user_context = UserContext()

    def test_get_user_context_does_not_raise_error_if_user_context_is_present(self):
        self.policy_factory._user_context = self.user_context
        user_context = self.policy_factory.get_user_context()
        assert user_context is self.policy_factory._user_context

    def test_get_user_context_raises_NoUserContextException_if_user_context_is_none(
        self,
    ):
        with pytest.raises(NoUserContextException):
            self.policy_factory.get_user_context()

    def test_register_authentication_policy_appends_policy_to_authentication_policies(
        self,
    ):
        dummy_policy = Mock()

        self.policy_factory.register_authentication_policy(dummy_policy)

        assert len(self.policy_factory._authorization_policies) == 0
        assert len(self.policy_factory._authentication_policies) == 1
        assert self.policy_factory._authentication_policies[0] is dummy_policy

    def test_register_authorization_policy_appends_policy_to_authorization_policies(
        self,
    ):
        dummy_policy = Mock()

        self.policy_factory.register_authorization_policy(dummy_policy)

        assert len(self.policy_factory._authentication_policies) == 0
        assert len(self.policy_factory._authorization_policies) == 1
        assert self.policy_factory._authorization_policies[0] is dummy_policy

    def test_apply_policies_raises_NoAuthenticationPoliciesToApplyException_if_no_authentication_policies_are_registered(
        self,
    ):
        with pytest.raises(NoAuthenticationPoliciesToApplyException):
            self.policy_factory._apply_policies_decorated_function_wrapper_implementation(
                Mock()
            )

    def test_apply_policies_raises_NoAuthorizationPoliciesToApplyException_if_no_authorization_policies_are_registered(
        self,
    ):
        self.policy_factory._authentication_policies.append(Mock())

        with pytest.raises(NoAuthorizationPoliciesToApplyException):
            self.policy_factory._apply_policies_decorated_function_wrapper_implementation(
                Mock()
            )

    def test_apply_policies_calls_authenticate_and_authorize(self):
        spy_policy_factory_authenticate = Mock()
        spy_policy_factory_authorize = Mock()

        spy_policy_factory_authenticate.return_value = self.user_context
        self.policy_factory._authenticate = spy_policy_factory_authenticate
        self.policy_factory._authorize = spy_policy_factory_authorize

        self.policy_factory._authentication_policies.append(Mock())
        self.policy_factory._authorization_policies.append(Mock())
        self.policy_factory._apply_policies_decorated_function_wrapper_implementation(
            self.request_context
        )

        spy_policy_factory_authenticate.assert_called_once()
        spy_policy_factory_authorize.assert_called_once_with(
            self.user_context, self.request_context
        )

    @patch(
        "inuits_policy_based_auth.authentication.base_authentication_policy.BaseAuthenticationPolicy.__abstractmethods__",
        set(),
    )
    def test_authenticate_applies_authentication_policies(self):
        policy_1 = BaseAuthenticationPolicy()  # type: ignore
        policy_2 = BaseAuthenticationPolicy()  # type: ignore
        spy_policy_1_apply = Mock()
        spy_policy_2_apply = Mock()

        spy_policy_1_apply.return_value = self.user_context
        spy_policy_2_apply.return_value = self.user_context
        policy_1.apply = spy_policy_1_apply
        policy_2.apply = spy_policy_2_apply
        self.policy_factory._authentication_policies = [policy_1, policy_2]

        user_context = self.policy_factory._authenticate()

        spy_policy_1_apply.assert_called_once()
        spy_policy_2_apply.assert_called_once()
        assert user_context is self.user_context

    def test_authorize_allows_access_and_stops_execution_if_policy_context_access_verdict_is_true(
        self,
    ):
        self._prepare_test_authorize()
        self.policy_context.access_verdict = True

        self.policy_factory._authorize(self.user_context, self.request_context)

        self.spy_policy_1_apply.assert_called_once()
        self.spy_policy_2_apply.assert_not_called()

    def test_authorize_denies_access_and_stops_execution_if_policy_context_access_verdict_is_false(
        self,
    ):
        self._prepare_test_authorize()
        self.policy_context.access_verdict = False

        with pytest.raises(Forbidden):
            self.policy_factory._authorize(self.user_context, self.request_context)

        self.spy_policy_1_apply.assert_called_once()
        self.spy_policy_2_apply.assert_not_called()

    def test_authorize_denies_access_if_policy_context_access_verdict_is_none(self):
        self._prepare_test_authorize()
        self.policy_context.access_verdict = None

        with pytest.raises(Forbidden):
            self.policy_factory._authorize(self.user_context, self.request_context)

        self.spy_policy_1_apply.assert_called_once()
        self.spy_policy_2_apply.assert_called_once()

    @patch(
        "inuits_policy_based_auth.authorization.base_authorization_policy.BaseAuthorizationPolicy.__abstractmethods__",
        set(),
    )
    def _prepare_test_authorize(self):
        policy_1 = BaseAuthorizationPolicy()  # type: ignore
        policy_2 = BaseAuthorizationPolicy()  # type: ignore
        self.spy_policy_1_apply = Mock()
        self.spy_policy_2_apply = Mock()

        self.spy_policy_1_apply.return_value = self.policy_context
        self.spy_policy_2_apply.return_value = self.policy_context
        policy_1.apply = self.spy_policy_1_apply
        policy_2.apply = self.spy_policy_2_apply
        self.policy_factory._authorization_policies = [policy_1, policy_2]
