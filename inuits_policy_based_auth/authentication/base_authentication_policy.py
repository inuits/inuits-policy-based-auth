from abc import abstractmethod
from inuits_policy_based_auth.base_policy import BasePolicy
from inuits_policy_based_auth.contexts.user_context import UserContext
from inuits_policy_based_auth.exceptions import (
    AuthenticateMethodDidNotReturnObjectOfTypeUserContextException,
)


class BaseAuthenticationPolicy(BasePolicy):
    """
    An abstract class used as an interface for concrete implementations of authentication policies.

    Methods
    -------
    authenticate(user_context)
        authenticates a user
    """

    def apply(self, user_context, request_context=None):
        user_context = self.authenticate(user_context)
        if not isinstance(user_context, UserContext):
            raise AuthenticateMethodDidNotReturnObjectOfTypeUserContextException()

        return user_context

    @abstractmethod
    def authenticate(self, user_context: UserContext) -> UserContext:
        """Authenticates a user.

        Parameters
        ----------
        user_context : UserContext
            an object containing data about the authenticated user

        Returns
        -------
        UserContext
            an object containing data about the authenticated user
        """

        pass
