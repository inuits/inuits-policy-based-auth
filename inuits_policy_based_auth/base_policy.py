from abc import ABC, abstractmethod
from inuits_policy_based_auth.contexts.request_context import RequestContext
from inuits_policy_based_auth.contexts.user_context import UserContext


class BasePolicy(ABC):
    """
    An abstract class used as an interface for the abstract base authentication/authorization policy.

    Methods
    -------
    apply(user_context, request_context)
        applies the policy
    """

    @abstractmethod
    def apply(
        self, user_context: UserContext, request_context: RequestContext | None
    ) -> UserContext:
        """Applies the policy.

        Parameters
        ----------
        user_context : UserContext
            an object containing data about the authenticated user
        request_context : RequestContext, optional
            an object containing data about the context of a request

        Returns
        -------
        UserContext
            an object containing data about the authenticated user

        Raises
        ------
        AuthenticateMethodDidNotReturnObjectOfTypeUserContextException
            if the authenticate method does not return an object of type UserContext
        """

        pass
