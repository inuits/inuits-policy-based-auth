import functools

from inuits_policy_based_auth.authentication.authenticator import Authenticator
from inuits_policy_based_auth.authorization.base_policy import BasePolicy
from inuits_policy_based_auth.authorization.context import Context
from inuits_policy_based_auth.inuits_policy_based_auth_exceptions import (
    NoStrategySetForAuthenticatorException,
    NoPoliciesToApplyException,
    NoUserAuthDataException,
)
from inuits_policy_based_auth.user_auth_data import UserAuthData
from werkzeug.exceptions import Unauthorized, Forbidden


class PolicyFactory:
    def __init__(self, authenticator: Authenticator, logger):
        self._authenticator = authenticator
        self._logger = logger
        self._user_auth_data = None
        self._policies: list[BasePolicy] = []

    @property
    def authenticator(self):
        return self._authenticator

    @property
    def logger(self):
        return self._logger

    def get_user_auth_data(self) -> UserAuthData:
        if not self._user_auth_data:
            raise NoUserAuthDataException()
        return self._user_auth_data

    def register(self, policy: BasePolicy):
        self._policies.append(policy)

    def apply_policies(self, context: Context):
        def decorator(decorated_function):
            @functools.wraps(decorated_function)
            def decorated_function_wrapper(*args, **kwargs):
                if not self._authenticator.strategy:
                    raise NoStrategySetForAuthenticatorException()
                if len(self._policies) <= 0:
                    raise NoPoliciesToApplyException()

                raised_error = None
                for policy in self._policies:
                    try:
                        self._user_auth_data = policy.apply(
                            self._authenticator, context
                        )
                        return decorated_function(*args, **kwargs)
                    except (Unauthorized, Forbidden) as error:
                        raised_error = error
                        continue

                if isinstance(raised_error, Unauthorized):
                    raise Unauthorized(str(raised_error))
                else:
                    raise Forbidden(str(raised_error))

            return decorated_function_wrapper

        return decorator
