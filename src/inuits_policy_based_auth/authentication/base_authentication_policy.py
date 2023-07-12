from abc import ABC, abstractmethod
from inuits_policy_based_auth.contexts import UserContext
from inuits_policy_based_auth.exceptions import (
    AuthenticateMethodDidNotReturnObjectOfTypeUserContextException,
)


class BaseAuthenticationPolicy(ABC):
    """
    An abstract class used as an interface for concrete implementations of
    authentication policies.

    Methods
    -------
    apply(user_context):
        Applies the policy.

    authenticate(user_context):
        Authenticates a user.
    """

    def apply(self, user_context: UserContext) -> UserContext:
        """Applies the policy.

        Parameters
        ----------
        user_context : UserContext
            An object containing data about the authenticated user.

        Returns
        -------
        UserContext
            An object containing data about the authenticated user.

        Raises
        ------
        AuthenticateMethodDidNotReturnObjectOfTypeUserContextException:
            If the authenticate method does not return an object of type UserContext.
        Unauthorized:
            If the user is not authenticated.
        """

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
            An object containing data about the user to be authenticated.

        Returns
        -------
        UserContext
            An object containing data about the authenticated user.

        Raises
        ------
        Unauthorized:
            If the user is not authenticated.
        """

        pass
