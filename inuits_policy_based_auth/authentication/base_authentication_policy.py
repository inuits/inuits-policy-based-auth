from abc import ABC, abstractmethod
from inuits_policy_based_auth.contexts import UserContext
from inuits_policy_based_auth.exceptions import (
    AuthenticateMethodDidNotReturnObjectOfTypeUserContextException,
)


class BaseAuthenticationPolicy(ABC):
    """
    An abstract class used as an interface for concrete implementations of authentication policies.

    Methods
    -------
    apply(user_context)
        applies the policy
    authenticate(user_context)
        authenticates a user
    """

    def apply(self, user_context: UserContext) -> UserContext:
        """Applies the policy.

        Parameters
        ----------
        user_context : UserContext
            an object containing data about the authenticated user

        Returns
        -------
        UserContext
            an object containing data about the authenticated user

        Raises
        ------
        AuthenticateMethodDidNotReturnObjectOfTypeUserContextException
            if the authenticate method does not return an object of type UserContext
        Unauthorized
            if the user is not authenticated
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
            an object containing data about the authenticated user

        Returns
        -------
        UserContext
            an object containing data about the authenticated user

        Raises
        ------
        Unauthorized
            if the user is not authenticated
        """

        pass
