from abc import ABC, abstractmethod
from inuits_policy_based_auth.authentication.authenticator import Authenticator
from inuits_policy_based_auth.authorization.context import Context
from inuits_policy_based_auth.user_auth_data import UserAuthData
from inuits_policy_based_auth.inuits_policy_based_auth_exceptions import (
    AuthenticateMethodDidNotReturnObjectOfTypeUserAuthData,
)


class BasePolicy(ABC):
    def apply(self, authenticator: Authenticator, context: Context):
        user_auth_data = self.authenticate(authenticator, context)
        if not isinstance(user_auth_data, UserAuthData):
            raise AuthenticateMethodDidNotReturnObjectOfTypeUserAuthData()

        self.authorize(user_auth_data, context)
        return user_auth_data

    @abstractmethod
    def authenticate(
        self, authenticator: Authenticator, context: Context
    ) -> UserAuthData:
        pass

    @abstractmethod
    def authorize(self, user_auth_data: UserAuthData, context: Context):
        pass
