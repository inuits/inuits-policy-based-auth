from abc import ABC, abstractmethod
from inuits_policy_based_auth.user_auth_data import UserAuthData


class Strategy(ABC):
    @abstractmethod
    def authenticate(self) -> UserAuthData:
        pass
