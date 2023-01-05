from abc import ABC, abstractmethod
from inuits_policy_based_auth.authentication.user_auth_data import UserAuthData


class Strategy(ABC):
    """
    An abstract class used as an interface for concrete implementations of authentication.

    Methods
    -------
    authenticate()
        authenticates a user
    """

    @abstractmethod
    def authenticate(self) -> UserAuthData:
        """Authenticates a user.

        Returns
        -------
        UserAuthData
            an object containing data about the authenticated user

        Raises
        ------
        Unauthorized
            if the user is not authenticated
        """

        pass
