from inuits_policy_based_auth.authentication.strategy import Strategy
from inuits_policy_based_auth.user_auth_data import UserAuthData


class Authenticator:
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
        return self._strategy.authenticate()
