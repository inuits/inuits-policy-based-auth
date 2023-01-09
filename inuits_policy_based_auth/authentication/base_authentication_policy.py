from abc import abstractmethod
from inuits_policy_based_auth.base_policy import BasePolicy
from inuits_policy_based_auth.contexts.request_context import RequestContext
from inuits_policy_based_auth.contexts.user_context import UserContext
from inuits_policy_based_auth.exceptions import (
    AuthenticateMethodDidNotReturnObjectOfTypeUserContext,
)


class BaseAuthenticationPolicy(BasePolicy):
    """
    An abstract class used as an interface for concrete implementations of authentication policies.

    Methods
    -------
    authenticate(user_context, request_context)
        authenticates a user
    """

    def apply(self, user_context: UserContext, request_context: RequestContext):
        user_context = self.authenticate(user_context, request_context)
        if not isinstance(user_context, UserContext):
            raise AuthenticateMethodDidNotReturnObjectOfTypeUserContext()

        return user_context

    @abstractmethod
    def authenticate(
        self, user_context: UserContext, request_context: RequestContext
    ) -> UserContext:
        """Authenticates a user.

        Parameters
        ----------
        user_context : UserContext
            an object containing data about the authenticated user
        request_context : RequestContext
            an object containing data about the context of a request

        Returns
        -------
        UserContext
            an object containing data about the authenticated user
        """

        pass
