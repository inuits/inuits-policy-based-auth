from abc import ABC, abstractmethod
from inuits_policy_based_auth.contexts.user_context import UserContext


class Strategy(ABC):
    """
    An abstract class used as an interface for concrete implementations of authentication.

    Methods
    -------
    authenticate()
        authenticates a user
    """

    @abstractmethod
    def authenticate(self) -> UserContext:
        """Authenticates a user.

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
