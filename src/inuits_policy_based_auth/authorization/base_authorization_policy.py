from abc import ABC, abstractmethod
from inuits_policy_based_auth.contexts import PolicyContext, RequestContext, UserContext
from inuits_policy_based_auth.exceptions import (
    AuthorizeMethodDidNotReturnObjectOfTypePolicyContextException,
)


class BaseAuthorizationPolicy(ABC):
    """
    An abstract class used as an interface for concrete implementations of
    authorization policies.

    Methods
    -------
    apply(user_context, request_context):
        Applies the policy.

    authorize(user_context, request_context):
        Authorizes a user.
    """

    def apply(
        self,
        policy_context: PolicyContext,
        user_context: UserContext,
        request_context: RequestContext,
    ) -> PolicyContext:
        """Applies the policy.

        Sets policy_context.access_verdict to its default value None before authorizing.

        Parameters
        ----------
        policy_context : PolicyContext
            An object containing data about the context of an applied
            authorization policy.
        user_context : UserContext
            An object containing data about the authenticated user.
        request_context : RequestContext
            An object containing data about the context of a request.

        Returns
        -------
        PolicyContext
            An object containing data about the context of an applied
            authorization policy.

        Raises
        ------
        AuthorizeMethodDidNotReturnObjectOfTypePolicyContextException:
            If the authorize method does not return an object of type
            PolicyContext.
        """

        policy_context.access_verdict = None
        policy_context = self.authorize(policy_context, user_context, request_context)
        if not isinstance(policy_context, PolicyContext):
            raise AuthorizeMethodDidNotReturnObjectOfTypePolicyContextException()

        return policy_context

    @abstractmethod
    def authorize(
        self,
        policy_context: PolicyContext,
        user_context: UserContext,
        request_context: RequestContext,
    ) -> PolicyContext:
        """Authorizes a user.

        Parameters
        ----------
        policy_context : PolicyContext
            An object containing data about the context of an applied
            authorization policy.
        user_context : UserContext
            An object containing data about the authenticated user.
        request_context : RequestContext, optional
            An object containing data about the context of a request.

        Returns
        -------
        PolicyContext
            An object containing data about the context of an applied
            authorization policy.
        """

        pass
