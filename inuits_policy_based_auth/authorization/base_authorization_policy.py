from abc import abstractmethod
from inuits_policy_based_auth.base_policy import BasePolicy
from inuits_policy_based_auth.authentication.authenticator import Authenticator
from inuits_policy_based_auth.contexts.request_context import RequestContext
from inuits_policy_based_auth.contexts.user_context import UserContext
from inuits_policy_based_auth.exceptions import (
    AuthenticateMethodDidNotReturnObjectOfTypeUserContext,
)


class BaseAuthorizationPolicy(BasePolicy):
    """
    An abstract class used as an interface for concrete implementations of authorization policies.

    Methods
    -------
    authenticate(authenticator, request_context)
        authenticates a user
    authorize(user_context, request_context)
        authorizes a user
    """

    def apply(self, authenticator: Authenticator, request_context: RequestContext):
        user_context = self.authenticate(authenticator, request_context)
        if not isinstance(user_context, UserContext):
            raise AuthenticateMethodDidNotReturnObjectOfTypeUserContext()

        self.authorize(user_context, request_context)
        return user_context

    @abstractmethod
    def authenticate(
        self, authenticator: Authenticator, request_context: RequestContext
    ) -> UserContext:
        """Authenticates a user.

        Parameters
        ----------
        authenticator : Authenticator
            the authenticator used to authenticate a user
        request_context : RequestContext
            an object containing data about the context of a request

        Returns
        -------
        UserContext
            an object containing data about the authenticated user
        """

        pass

    @abstractmethod
    def authorize(self, user_context: UserContext, request_context: RequestContext):
        """Authorizes a user.

        Parameters
        ----------
        user_context : UserContext
            an object containing data about the authenticated user
        request_context : RequestContext
            an object containing data about the context of a request

        Raises
        ------
        Forbidden
            if the user is not authorized
        """

        pass
