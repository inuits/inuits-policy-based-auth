import functools

from inuits_policy_based_auth.authorization.base_authorization_policy import (
    BaseAuthorizationPolicy,
)
from inuits_policy_based_auth.contexts.request_context import RequestContext
from inuits_policy_based_auth.contexts.user_context import UserContext
from inuits_policy_based_auth.exceptions import (
    NoAuthorizationPoliciesToApplyException,
    NoUserContextException,
)
from werkzeug.exceptions import Unauthorized, Forbidden


class PolicyFactory:
    """
    A class used to apply policies.

    Attributes
    ----------
    _logger : Unknown
        a logger to log information
    _user_context : UserContext
        an object containing data about the authenticated user
    _policies : list[BaseAuthorizationPolicy]
        a list of policies to apply

    Methods
    -------
    get_user_context()
        returns an object of type UserContext
    register_authorization_policy(policy)
        appends a policy to the list of authorization policies to be applied
    apply_policies(request_context)
        applies the policies to determine access
    """

    def __init__(self, logger):
        """
        Parameters
        ----------
        logger : Unknown
            a logger to log information
        """

        self._logger = logger
        self._user_context = None
        self._authorization_policies: list[BaseAuthorizationPolicy] = []

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

    def register_authorization_policy(self, policy: BaseAuthorizationPolicy):
        """Appends a policy to the list of authorization policies to be applied.

        Parameters
        ----------
        policy : BaseAuthorizationPolicy
            a policy to be applied
        """

        self._authorization_policies.append(policy)

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
        NoAuthorizationPoliciesToApplyException
            if the policies list is empty
        Unauthorized
            if a user is not authenticated
        Forbidden
            if a user is not authorized
        """

        def decorator(decorated_function):
            @functools.wraps(decorated_function)
            def decorated_function_wrapper(*args, **kwargs):
                if len(self._authorization_policies) <= 0:
                    raise NoAuthorizationPoliciesToApplyException()

                self._user_context = UserContext()

                raised_error = None
                for policy in self._authorization_policies:
                    try:
                        self._user_context = policy.apply(
                            self._user_context, request_context
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
