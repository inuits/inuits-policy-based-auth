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
    InvalidFallbackKey,
    NoFallbackKeySet,
)
from unittest.mock import Mock, patch
from werkzeug.exceptions import Forbidden


class TestPolicyFactory:
    def setup_method(self):
        self.policy_factory = PolicyFactory()
        self.policy_context = PolicyContext()
        self.request_context = RequestContext(None)
        self.user_context = UserContext()
        self.key = "tests.unit"

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

        self.policy_factory.register_authentication_policy(self.key, dummy_policy)

        assert len(self.policy_factory._authorization_policies) == 0
        assert len(self.policy_factory._authentication_policies) == 1
        assert self.policy_factory._authentication_policies[self.key][0] is dummy_policy

    def test_register_authorization_policy_appends_policy_to_authorization_policies(
        self,
    ):
        dummy_policy = Mock()

        self.policy_factory.register_authorization_policy(self.key, dummy_policy)

        assert len(self.policy_factory._authentication_policies) == 0
        assert len(self.policy_factory._authorization_policies) == 1
        assert self.policy_factory._authorization_policies[self.key][0] is dummy_policy

    def test_set_fallback_key_for_policy_mapping_sets_key(self):
        self.policy_factory._authentication_policies.update({self.key: [Mock()]})
        self.policy_factory._authorization_policies.update({self.key: [Mock()]})

        self.policy_factory.set_fallback_key_for_policy_mapping(self.key)

        assert self.policy_factory._fallback_key_for_policy_mapping == self.key

    def test_set_fallback_key_for_policy_mapping_raises_InvalidFallbackKey_if_key_is_an_empty_string(
        self,
    ):
        self.policy_factory._authentication_policies.update({self.key: [Mock()]})
        self.policy_factory._authorization_policies.update({self.key: [Mock()]})

        with pytest.raises(InvalidFallbackKey):
            self.policy_factory.set_fallback_key_for_policy_mapping("")

    def test_set_fallback_key_for_policy_mapping_raises_InvalidFallbackKey_if_key_is_not_registered_in_authentication_policies(
        self,
    ):
        self.policy_factory._authentication_policies.update({"different_key": [Mock()]})
        self.policy_factory._authorization_policies.update({self.key: [Mock()]})

        with pytest.raises(InvalidFallbackKey):
            self.policy_factory.set_fallback_key_for_policy_mapping(self.key)

    def test_set_fallback_key_for_policy_mapping_raises_InvalidFallbackKey_if_key_is_not_registered_in_authorization_policies(
        self,
    ):
        self.policy_factory._authentication_policies.update({self.key: [Mock()]})
        self.policy_factory._authorization_policies.update({"different_key": [Mock()]})

        with pytest.raises(InvalidFallbackKey):
            self.policy_factory.set_fallback_key_for_policy_mapping(self.key)

    def test_set_fallback_key_for_policy_mapping_raises_InvalidFallbackKey_if_key_is_not_registered_in_authentication_and_authorization_policies(
        self,
    ):
        self.policy_factory._authentication_policies.update({"different_key": [Mock()]})
        self.policy_factory._authorization_policies.update({"different_key": [Mock()]})

        with pytest.raises(InvalidFallbackKey):
            self.policy_factory.set_fallback_key_for_policy_mapping(self.key)

    def test_apply_policies_raises_NoAuthenticationPoliciesToApplyException_if_no_authentication_policies_are_registered(
        self,
    ):
        with pytest.raises(NoAuthenticationPoliciesToApplyException):
            self.policy_factory._apply_policies_decorated_function_wrapper_implementation(
                Mock(), Mock()
            )

    def test_apply_policies_raises_NoAuthorizationPoliciesToApplyException_if_no_authorization_policies_are_registered(
        self,
    ):
        self.policy_factory._authentication_policies.update({self.key: [Mock()]})

        with pytest.raises(NoAuthorizationPoliciesToApplyException):
            self.policy_factory._apply_policies_decorated_function_wrapper_implementation(
                Mock(), Mock()
            )

    def test_apply_policies_calls_authenticate_and_authorize(self):
        spy_decorated_function = Mock()
        spy_policy_factory_authenticate = Mock()
        spy_policy_factory_authorize = Mock()

        spy_policy_factory_authenticate.return_value = self.user_context
        self.policy_factory._authenticate = spy_policy_factory_authenticate
        self.policy_factory._authorize = spy_policy_factory_authorize

        self.policy_factory._authentication_policies.update({self.key: [Mock()]})
        self.policy_factory._authorization_policies.update({self.key: [Mock()]})
        self.policy_factory._apply_policies_decorated_function_wrapper_implementation(
            spy_decorated_function, self.request_context
        )

        spy_policy_factory_authenticate.assert_called_once_with(spy_decorated_function)
        spy_policy_factory_authorize.assert_called_once_with(
            spy_decorated_function, self.user_context, self.request_context
        )

    @patch(
        "inuits_policy_based_auth.authentication.base_authentication_policy.BaseAuthenticationPolicy.__abstractmethods__",
        set(),
    )
    def test_authenticate_applies_authentication_policies(self):
        spy_policy_factory_get_key_for_policy_mapping = Mock()
        dummy_decorated_function = Mock()
        policy_1 = BaseAuthenticationPolicy()  # type: ignore
        policy_2 = BaseAuthenticationPolicy()  # type: ignore
        spy_policy_1_apply = Mock()
        spy_policy_2_apply = Mock()

        spy_policy_factory_get_key_for_policy_mapping.return_value = self.key
        self.policy_factory._get_key_for_policy_mapping = (
            spy_policy_factory_get_key_for_policy_mapping
        )
        spy_policy_1_apply.return_value = self.user_context
        spy_policy_2_apply.return_value = self.user_context
        policy_1.apply = spy_policy_1_apply
        policy_2.apply = spy_policy_2_apply
        self.policy_factory._authentication_policies.update(
            {self.key: [policy_1, policy_2]}
        )

        user_context = self.policy_factory._authenticate(dummy_decorated_function)

        spy_policy_factory_get_key_for_policy_mapping.assert_called_once_with(
            self.policy_factory._authentication_policies, dummy_decorated_function
        )
        spy_policy_1_apply.assert_called_once()
        spy_policy_2_apply.assert_called_once()
        assert user_context is self.user_context

    def test_authorize_allows_access_and_stops_execution_if_policy_context_access_verdict_is_true(
        self,
    ):
        self._prepare_test_authorize()
        self.policy_context.access_verdict = True

        self.policy_factory._authorize(
            self.dummy_decorated_function, self.user_context, self.request_context
        )

        self.spy_policy_factory_get_key_for_policy_mapping.assert_called_once_with(
            self.policy_factory._authorization_policies, self.dummy_decorated_function
        )
        self.spy_policy_1_apply.assert_called_once()
        self.spy_policy_2_apply.assert_not_called()

    def test_authorize_denies_access_and_stops_execution_if_policy_context_access_verdict_is_false(
        self,
    ):
        self._prepare_test_authorize()
        self.policy_context.access_verdict = False

        with pytest.raises(Forbidden):
            self.policy_factory._authorize(
                self.dummy_decorated_function, self.user_context, self.request_context
            )

        self.spy_policy_factory_get_key_for_policy_mapping.assert_called_once_with(
            self.policy_factory._authorization_policies, self.dummy_decorated_function
        )
        self.spy_policy_1_apply.assert_called_once()
        self.spy_policy_2_apply.assert_not_called()

    def test_authorize_denies_access_if_policy_context_access_verdict_is_none(self):
        self._prepare_test_authorize()
        self.policy_context.access_verdict = None

        with pytest.raises(Forbidden):
            self.policy_factory._authorize(
                self.dummy_decorated_function, self.user_context, self.request_context
            )

        self.spy_policy_factory_get_key_for_policy_mapping.assert_called_once_with(
            self.policy_factory._authorization_policies, self.dummy_decorated_function
        )
        self.spy_policy_1_apply.assert_called_once()
        self.spy_policy_2_apply.assert_called_once()

    def test_get_key_for_policy_mapping_gets_key(self):
        stub_decorated_function = Mock()
        policy_dict = {self.key: [], "different_key": []}

        stub_decorated_function.__module__ = f"{self.key}.example"
        key = self.policy_factory._get_key_for_policy_mapping(
            policy_dict, stub_decorated_function
        )

        assert key == self.key

    def test_get_key_for_policy_mapping_uses_fallback_key(self):
        stub_decorated_function = Mock()
        different_key = "different_key"
        policy_dict = {self.key: [], different_key: []}

        stub_decorated_function.__module__ = f"invalid_module.{self.key}.example"
        self.policy_factory._fallback_key_for_policy_mapping = different_key

        key = self.policy_factory._get_key_for_policy_mapping(
            policy_dict, stub_decorated_function
        )

        assert key == different_key

    def test_get_key_for_policy_mapping_raises_NoFallbackKeySet_if_no_fallback_key_is_set(
        self,
    ):
        stub_decorated_function = Mock()
        different_key = "different_key"
        policy_dict = {self.key: [], different_key: []}

        stub_decorated_function.__module__ = f"invalid_module.{self.key}.example"
        with pytest.raises(NoFallbackKeySet):
            self.policy_factory._get_key_for_policy_mapping(
                policy_dict, stub_decorated_function
            )

    @patch(
        "inuits_policy_based_auth.authorization.base_authorization_policy.BaseAuthorizationPolicy.__abstractmethods__",
        set(),
    )
    def _prepare_test_authorize(self):
        self.spy_policy_factory_get_key_for_policy_mapping = Mock()
        self.dummy_decorated_function = Mock()
        policy_1 = BaseAuthorizationPolicy()  # type: ignore
        policy_2 = BaseAuthorizationPolicy()  # type: ignore
        self.spy_policy_1_apply = Mock()
        self.spy_policy_2_apply = Mock()

        self.spy_policy_factory_get_key_for_policy_mapping.return_value = self.key
        self.policy_factory._get_key_for_policy_mapping = (
            self.spy_policy_factory_get_key_for_policy_mapping
        )
        self.spy_policy_1_apply.return_value = self.policy_context
        self.spy_policy_2_apply.return_value = self.policy_context
        policy_1.apply = self.spy_policy_1_apply
        policy_2.apply = self.spy_policy_2_apply
        self.policy_factory._authorization_policies.update(
            {self.key: [policy_1, policy_2]}
        )
