import inspect
import os
import re as regex

from functools import wraps
from inuits_policy_based_auth.authentication.base_authentication_policy import (
    BaseAuthenticationPolicy,
)
from inuits_policy_based_auth.authorization.base_authorization_policy import (
    BaseAuthorizationPolicy,
)
from inuits_policy_based_auth.contexts import PolicyContext, RequestContext, UserContext
from inuits_policy_based_auth.exceptions import (
    PolicyFactoryException,
    NoUserContextException,
    NoAuthenticationPoliciesToApplyException,
    NoAuthorizationPoliciesToApplyException,
    InvalidFallbackKey,
    NoFallbackKeySet,
)
from werkzeug.exceptions import Forbidden


class PolicyFactory:
    """
    A class used to apply policies.

    Methods
    -------
    get_user_context()
        Returns an object of type UserContext.

    register_authentication_policy(key, policy)
        Appends a policy to the list of authentication policies to be applied
        mapped to a key.

    register_authorization_policy(key, policy)
        Appends a policy to the list of authorization policies to be applied
        mapped to a key.

    apply_policies(request_context)
        Applies registered policies to determine access.

    set_fallback_key_for_policy_mapping(key)
        Sets a fallback key for policy mapping if no key matches the first part
        of the module name of endpoints decorated by the policy factory.
    """

    def __init__(self):
        self._user_context = None
        self._authentication_policies: dict[str, list[BaseAuthenticationPolicy]] = {}
        self._authorization_policies: dict[str, list[BaseAuthorizationPolicy]] = {}
        self._fallback_key_for_policy_mapping = ""

    def get_user_context(self) -> UserContext:
        """
        Returns an object of type UserContext.

        Returns
        -------
        UserContext
            An object containing data about the authenticated user.

        Raises
        ------
        NoUserContextException
            If there is no user auth data yet.
        """

        if not self._user_context:
            raise NoUserContextException()
        return self._user_context

    def register_authentication_policy(
        self, key: str, policy: BaseAuthenticationPolicy
    ):
        """
        Appends a policy to the list of authentication policies to be applied mapped
        to a key.

        Parameters
        ----------
        key : str
            A key that matches the first part of the module name of endpoints decorated
            by the policy factory.
        policy : BaseAuthenticationPolicy
            A policy to be applied.
        """

        policies = self._authentication_policies.get(key)
        if policies:
            policies.append(policy)
        else:
            self._authentication_policies.update({key: [policy]})

    def register_authorization_policy(self, key: str, policy: BaseAuthorizationPolicy):
        """
        Appends a policy to the list of authorization policies to be applied mapped
        to a key.

        Parameters
        ----------
        key : str
            A key that matches the first part of the module name of endpoints decorated
            by the policy factory.
        policy : BaseAuthorizationPolicy
            A policy to be applied.
        """

        policies = self._authorization_policies.get(key)
        if policies:
            policies.append(policy)
        else:
            self._authorization_policies.update({key: [policy]})

    def set_fallback_key_for_policy_mapping(self, key: str):
        """
        Sets a key for policy mapping to fallback if no key matches the first part of
        the module name of endpoints decorated by the policy factory.

        Parameters
        ----------
        key : str
            A fallback key for policy mapping.

        Raises
        ------
        InvalidFallbackKey
            If provided key is not registered in either authentication policies,
            authorization policies, or both.
        """

        if (
            key != ""
            and self._authentication_policies.get(key)
            and self._authorization_policies.get(key)
        ):
            self._fallback_key_for_policy_mapping = key
        else:
            raise InvalidFallbackKey(key)

    def authenticate(self):
        """
        Applies registered authentication policies to determine access.

        Returns
        -------
        function
            A decorator to decorate endpoints with.

        Raises
        ------
        NoAuthenticationPoliciesToApplyException
            If no authentication policies are registered.
        Unauthorized
            If user is not authenticated.
        NoFallbackKeySet
            If no fallback key for policy mapping is set.
        """

        def decorator(decorated_function):
            @wraps(decorated_function)
            def decorated_function_wrapper(*args, **kwargs):
                if len(self._authentication_policies) <= 0:
                    raise NoAuthenticationPoliciesToApplyException()

                if self.__is_test_environment(decorated_function):
                    import traceback
                    from flask import make_response

                    try:
                        self._user_context = self._authenticate(decorated_function)
                    except (TypeError, PolicyFactoryException) as error:
                        return make_response(
                            {
                                "message": str(error),
                                "stacktrace": traceback.format_exc(),
                            },
                            500,
                        )
                else:
                    self._user_context = self._authenticate(decorated_function)

                return decorated_function(*args, **kwargs)

            return decorated_function_wrapper

        return decorator

    def apply_policies(self, request_context: RequestContext):
        """
        Applies registered policies to determine access.

        The first allowing policy will stop execution and allow access.
        The first denying policy will stop execution and deny access.
        If all policies are applied and none of them allowed or denied access
        (policy_context.access_verdict == None), then access is denied.

        Parameters
        ----------
        request_context : RequestContext
            An object containing data about the context of a request.

        Returns
        -------
        function
            A decorator to decorate endpoints with.

        Raises
        ------
        NoAuthenticationPoliciesToApplyException
            If no authentication policies are registered.
        NoAuthorizationPoliciesToApplyException
            If no authorization policies are registered.
        Unauthorized
            If user is not authenticated.
        Forbidden
            If user is not authorized.
        NoFallbackKeySet
            If no fallback key for policy mapping is set.
        """

        def decorator(decorated_function):
            @wraps(decorated_function)
            def decorated_function_wrapper(*args, **kwargs):
                if self.__is_test_environment(decorated_function):
                    import traceback
                    from flask import make_response

                    try:
                        self._apply_policies_decorated_function_wrapper_implementation(
                            decorated_function, request_context
                        )
                    except (TypeError, PolicyFactoryException) as error:
                        return make_response(
                            {
                                "message": str(error),
                                "stacktrace": traceback.format_exc(),
                            },
                            500,
                        )
                else:
                    self._apply_policies_decorated_function_wrapper_implementation(
                        decorated_function, request_context
                    )

                return decorated_function(*args, **kwargs)

            return decorated_function_wrapper

        return decorator

    def _apply_policies_decorated_function_wrapper_implementation(
        self, decorated_function, request_context: RequestContext
    ):
        if len(self._authentication_policies) <= 0:
            raise NoAuthenticationPoliciesToApplyException()
        if len(self._authorization_policies) <= 0:
            raise NoAuthorizationPoliciesToApplyException()

        self._user_context = self._authenticate(decorated_function)
        self._authorize(decorated_function, self._user_context, request_context)

    def _authenticate(self, decorated_function):
        user_context = UserContext()

        key = self._get_key_for_policy_mapping(
            self._authentication_policies, decorated_function
        )
        for policy in self._authentication_policies[key]:
            user_context = policy.apply(user_context)

        return user_context

    def _authorize(
        self,
        decorated_function,
        user_context: UserContext,
        request_context: RequestContext,
    ):
        policy_context = PolicyContext()

        key = self._get_key_for_policy_mapping(
            self._authorization_policies, decorated_function
        )
        for policy in self._authorization_policies[key]:
            policy_context = policy.apply(policy_context, user_context, request_context)

            if policy_context.access_verdict:
                return
            elif policy_context.access_verdict == False:
                break

        raise Forbidden()

    def _get_key_for_policy_mapping(self, policy_dict: dict, decorated_function) -> str:
        for key in policy_dict.keys():
            if regex.match(rf"^{key}.*", decorated_function.__module__) != None:
                return key

        if self._fallback_key_for_policy_mapping:
            return self._fallback_key_for_policy_mapping

        raise NoFallbackKeySet

    def __is_test_environment(self, decorated_function) -> bool:
        decorated_function_module = inspect.getmodule(decorated_function)
        if decorated_function_module:
            return (
                regex.match(
                    rf".*/inuits-policy-based-auth/{os.getenv('FLASK_APP')}$",
                    str(decorated_function_module.__file__),
                )
                != None
            )

        return False
