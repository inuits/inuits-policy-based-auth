import functools

from inuits_policy_based_auth.authentication.authenticator import Authenticator
from inuits_policy_based_auth.authorization.base_policy import BasePolicy
from inuits_policy_based_auth.contexts.request_context import RequestContext
from inuits_policy_based_auth.contexts.user_context import UserContext
from inuits_policy_based_auth.exceptions import (
    NoStrategySetForAuthenticatorException,
    NoPoliciesToApplyException,
    NoUserContextException,
)
from werkzeug.exceptions import Unauthorized, Forbidden


class PolicyFactory:
    """
    A class used to apply policies.

    Attributes
    ----------
    _authenticator : Authenticator
        the authenticator used to authenticate a user
    _logger : Unknown
        a logger to log information
    _user_context : UserContext
        an object containing data about the authenticated user
    _policies : list[BasePolicy]
        a list of policies to apply

    Methods
    -------
    get_user_context()
        returns an object of type UserContext
    register(policy)
        appends a policy to the list of policies to be applied
    apply_policies(request_context)
        applies the policies to determine access
    """

    def __init__(self, authenticator: Authenticator, logger):
        """
        Parameters
        ----------
        authenticator : Authenticator
            the authenticator used to authenticate a user
        logger : Unknown
            a logger to log information
        """

        self._authenticator = authenticator
        self._logger = logger
        self._user_context = None
        self._policies: list[BasePolicy] = []

    @property
    def authenticator(self):
        return self._authenticator

    @property
    def logger(self):
        return self._logger

    def get_user_context(self) -> UserContext:
        """Returns an object of type UserContext.

        Returns
        -------
        UserContext
            an object containing data about the authenticated user

        Raises
        ------
        NoUserContextException
            if there is no user auth data
        """

        if not self._user_context:
            raise NoUserContextException()
        return self._user_context

    def register(self, policy: BasePolicy):
        """Appends a policy to the list of policies to be applied.

        Parameters
        ----------
        policy : BasePolicy
            a policy to be applied
        """

        self._policies.append(policy)

    def apply_policies(self, request_context: RequestContext):
        """Applies the policies to determine access.

        The first succeeding policy will stop execution and provide access.

        Parameters
        ----------
        request_context : RequestContext
            an object containing data about the context of a request

        Returns
        -------
        function
            a decorator to decorate endpoints with

        Raises
        ------
        NoStrategySetForAuthenticatorException
            if no strategy is set for the authenticator
        NoPoliciesToApplyException
            if the policies list is empty
        Unauthorized
            if a user is not authenticated
        Forbidden
            if a user is not authorized
        """

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
                        self._user_context = policy.apply(
                            self._authenticator, request_context
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
