from functools import wraps
from inuits_policy_based_auth.authentication.base_authentication_policy import (
    BaseAuthenticationPolicy,
)
from inuits_policy_based_auth.authorization.base_authorization_policy import (
    BaseAuthorizationPolicy,
)
from inuits_policy_based_auth.contexts import PolicyContext, RequestContext, UserContext
from inuits_policy_based_auth.exceptions import (
    NoAuthenticationPoliciesToApplyException,
    NoAuthorizationPoliciesToApplyException,
    NoUserContextException,
)
from werkzeug.exceptions import Forbidden


class PolicyFactory:
    """
    A class used to apply policies.

    Properties
    ----------
    logger : Unknown
        a logger to log information

    Methods
    -------
    get_user_context()
        returns an object of type UserContext
    register_authentication_policy(policy)
        appends a policy to the list of authentication policies to be applied
    register_authorization_policy(policy)
        appends a policy to the list of authorization policies to be applied
    apply_policies(request_context)
        applies registered policies to determine access
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
        self._authentication_policies: list[BaseAuthenticationPolicy] = []
        self._authorization_policies: list[BaseAuthorizationPolicy] = []

    @property
    def logger(self):
        """A logger to log information."""

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
            if there is no user auth data yet
        """

        if not self._user_context:
            raise NoUserContextException()
        return self._user_context

    def register_authentication_policy(self, policy: BaseAuthenticationPolicy):
        """Appends a policy to the list of authentication policies to be applied.

        Parameters
        ----------
        policy : BaseAuthenticationPolicy
            a policy to be applied
        """

        self._authentication_policies.append(policy)

    def register_authorization_policy(self, policy: BaseAuthorizationPolicy):
        """Appends a policy to the list of authorization policies to be applied.

        Parameters
        ----------
        policy : BaseAuthorizationPolicy
            a policy to be applied
        """

        self._authorization_policies.append(policy)

    def authenticate(self):
        """Applies registered authentication policies to determine access.

        Returns
        -------
        function
            a decorator to decorate endpoints with

        Raises
        ------
        NoAuthenticationPoliciesToApplyException
            if no authentication policies are registered
        Unauthorized
            if user is not authenticated
        """

        def decorator(decorated_function):
            @wraps(decorated_function)
            def decorated_function_wrapper(*args, **kwargs):
                if len(self._authentication_policies) <= 0:
                    raise NoAuthenticationPoliciesToApplyException()

                self._user_context = self._authenticate()
                return decorated_function(*args, **kwargs)

            return decorated_function_wrapper

        return decorator

    def apply_policies(self, request_context: RequestContext):
        """Applies registered policies to determine access.

        The first allowing policy will stop execution and allow access.
        The first denying policy will stop execution and deny access.
        If all policies are applied and none of them allowed or denied access (policy_context.access_verdict == None), then access is denied.

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
        NoAuthenticationPoliciesToApplyException
            if no authentication policies are registered
        NoAuthorizationPoliciesToApplyException
            if no authorization policies are registered
        Unauthorized
            if user is not authenticated
        Forbidden
            if user is not authorized
        """

        def decorator(decorated_function):
            @wraps(decorated_function)
            def decorated_function_wrapper(*args, **kwargs):
                self._apply_policies_decorated_function_wrapper_implementation(
                    request_context
                )
                return decorated_function(*args, **kwargs)

            return decorated_function_wrapper

        return decorator

    def _apply_policies_decorated_function_wrapper_implementation(
        self, request_context: RequestContext
    ):
        if len(self._authentication_policies) <= 0:
            raise NoAuthenticationPoliciesToApplyException()
        if len(self._authorization_policies) <= 0:
            raise NoAuthorizationPoliciesToApplyException()

        self._user_context = self._authenticate()
        self._authorize(self._user_context, request_context)

    def _authenticate(self):
        user_context = UserContext()

        for policy in self._authentication_policies:
            user_context = policy.apply(user_context)

        return user_context

    def _authorize(self, user_context: UserContext, request_context: RequestContext):
        policy_context = PolicyContext()

        for policy in self._authorization_policies:
            policy_context = policy.apply(policy_context, user_context, request_context)

            if policy_context.access_verdict:
                return
            elif policy_context.access_verdict == False:
                break

        raise Forbidden()
