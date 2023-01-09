from abc import ABC, abstractmethod
from inuits_policy_based_auth.authentication.authenticator import Authenticator
from inuits_policy_based_auth.contexts.request_context import RequestContext
from inuits_policy_based_auth.exceptions import (
    AuthenticateMethodDidNotReturnObjectOfTypeUserAuthData,
)
from inuits_policy_based_auth.user_auth_data import UserAuthData


class BasePolicy(ABC):
    """
    An abstract class used as an interface for concrete implementations of policies.

    Methods
    -------
    apply(authenticator, request_context)
        applies the policy by executing the authenticate and authorize methods
    authenticate(authenticator, request_context)
        authenticates a user
    authorize(user_auth_data, request_context)
        authorizes a user
    """

    def apply(self, authenticator: Authenticator, request_context: RequestContext):
        """Applies the policy by executing the authenticate and authorize methods.

        Parameters
        ----------
        authenticator : Authenticator
            the authenticator used to authenticate a user
        request_context : RequestContext
            an object containing data about the context of a request

        Returns
        -------
        UserAuthData
            an object containing data about the authenticated user

        Raises
        ------
        AuthenticateMethodDidNotReturnObjectOfTypeUserAuthData
            if the authenticate method does not return an object of type UserAuthData
        """

        user_auth_data = self.authenticate(authenticator, request_context)
        if not isinstance(user_auth_data, UserAuthData):
            raise AuthenticateMethodDidNotReturnObjectOfTypeUserAuthData()

        self.authorize(user_auth_data, request_context)
        return user_auth_data

    @abstractmethod
    def authenticate(
        self, authenticator: Authenticator, request_context: RequestContext
    ) -> UserAuthData:
        """Authenticates a user.

        Parameters
        ----------
        authenticator : Authenticator
            the authenticator used to authenticate a user
        request_context : RequestContext
            an object containing data about the context of a request

        Returns
        -------
        UserAuthData
            an object containing data about the authenticated user
        """

        pass

    @abstractmethod
    def authorize(self, user_auth_data: UserAuthData, request_context: RequestContext):
        """Authorizes a user.

        Parameters
        ----------
        user_auth_data : UserAuthData
            an object containing data about the authenticated user
        request_context : RequestContext
            an object containing data about the context of a request

        Raises
        ------
        Forbidden
            if the user is not authorized
        """

        pass
