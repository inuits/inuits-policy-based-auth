from abc import ABC, abstractmethod
from inuits_policy_based_auth.authentication.authenticator import Authenticator
from inuits_policy_based_auth.contexts.request_context import RequestContext
from inuits_policy_based_auth.contexts.user_context import UserContext


class BasePolicy(ABC):
    """
    An abstract class used as an interface for the abstract base authentication/authorization policy.

    Methods
    -------
    apply(authenticator, request_context)
        applies the policy
    """

    @abstractmethod
    def apply(
        self, authenticator: Authenticator, request_context: RequestContext
    ) -> UserContext:
        """Applies the policy.

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

        Raises
        ------
        AuthenticateMethodDidNotReturnObjectOfTypeUserContext
            if the authenticate method does not return an object of type UserContext
        """

        pass
