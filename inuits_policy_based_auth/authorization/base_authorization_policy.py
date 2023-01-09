from abc import abstractmethod
from inuits_policy_based_auth.base_policy import BasePolicy
from inuits_policy_based_auth.contexts.request_context import RequestContext
from inuits_policy_based_auth.contexts.user_context import UserContext
from inuits_policy_based_auth.exceptions import (
    NoRequestContextInAuthorizationPolicyException,
)


class BaseAuthorizationPolicy(BasePolicy):
    """
    An abstract class used as an interface for concrete implementations of authorization policies.

    Methods
    -------
    authorize(user_context, request_context)
        authorizes a user
    """

    def apply(self, user_context, request_context):
        if not request_context:
            raise NoRequestContextInAuthorizationPolicyException()

        self.authorize(user_context, request_context)
        return user_context

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
