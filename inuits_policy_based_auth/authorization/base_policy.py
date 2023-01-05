from abc import ABC, abstractmethod
from inuits_policy_based_auth import Authenticator, Context, UserAuthData
from inuits_policy_based_auth.exceptions import (
    AuthenticateMethodDidNotReturnObjectOfTypeUserAuthData,
)


class BasePolicy(ABC):
    """
    An abstract class used as an interface for concrete implementations of policies.

    Methods
    -------
    apply(authenticator, context)
        applies the policy by executing the authenticate and authorize methods
    authenticate(authenticator, context)
        authenticates a user
    authorize(user_auth_data, context)
        authorizes a user
    """

    def apply(self, authenticator: Authenticator, context: Context):
        """Applies the policy by executing the authenticate and authorize methods.

        Parameters
        ----------
        authenticator : Authenticator
            the authenticator used to authenticate a user
        context : Context
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

        user_auth_data = self.authenticate(authenticator, context)
        if not isinstance(user_auth_data, UserAuthData):
            raise AuthenticateMethodDidNotReturnObjectOfTypeUserAuthData()

        self.authorize(user_auth_data, context)
        return user_auth_data

    @abstractmethod
    def authenticate(
        self, authenticator: Authenticator, context: Context
    ) -> UserAuthData:
        """Authenticates a user.

        Parameters
        ----------
        authenticator : Authenticator
            the authenticator used to authenticate a user
        context : Context
            an object containing data about the context of a request

        Returns
        -------
        UserAuthData
            an object containing data about the authenticated user
        """

        pass

    @abstractmethod
    def authorize(self, user_auth_data: UserAuthData, context: Context):
        """Authorizes a user.

        Parameters
        ----------
        user_auth_data : UserAuthData
            an object containing data about the authenticated user
        context : Context
            an object containing data about the context of a request

        Raises
        ------
        Forbidden
            if the user is not authorized
        """

        pass
