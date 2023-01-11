import pytest

from inuits_policy_based_auth import PolicyFactory
from inuits_policy_based_auth.contexts import UserContext
from inuits_policy_based_auth.exceptions import NoUserContextException


class TestPolicyFactory:
    def setup_method(self):
        self.policy_factory = PolicyFactory(None)

    def test_get_user_context_does_not_raise_error_if_user_context_is_present(self):
        self.policy_factory._user_context = UserContext()  # type: ignore

        try:
            user_context = self.policy_factory.get_user_context()
            assert user_context is self.policy_factory._user_context
        except Exception as error:
            pytest.fail(f"Unexpected error: {str(error)}")

    def test_get_user_context_raises_NoUserContextException_if_user_context_is_none(
        self,
    ):
        with pytest.raises(NoUserContextException):
            self.policy_factory.get_user_context()
