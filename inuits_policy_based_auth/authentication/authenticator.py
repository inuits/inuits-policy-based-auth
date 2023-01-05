from inuits_policy_based_auth import UserAuthData
from inuits_policy_based_auth.authentication.strategy import Strategy


class Authenticator:
    """
    A class used to authenticate a user.

    This class allows you to use any implementation to authenticate a user.
    The concrete implementation of authentication can be switched at runtime.

    Attributes
    ----------
    _strategy : Strategy
        a concrete implementation of authentication that is used to authenticate a user

    Methods
    -------
    authenticate()
        calls the authenticate method of a given strategy
    """

    @property
    def strategy(self):
        try:
            return self._strategy
        except:
            return None

    @strategy.setter
    def strategy(self, strategy: Strategy):
        self._strategy = strategy

    def authenticate(self) -> UserAuthData:
        """Calls the authenticate method of a given strategy.

        Returns
        -------
        UserAuthData
            an object containing data about the authenticated user
        """

        return self._strategy.authenticate()
