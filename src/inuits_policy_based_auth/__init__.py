"""
Module for securing API endpoints based on policies.

This module provides a generic and highly customizable way of securing
API endpoints based on policies using a simple decorator.
When dynamically loading policies from a custom configuration file, this
module will allow you to add new policies and override existing ones
to make it exactly fit your needs.

Classes
-------
    BaseAuthenticationPolicy
        used as an interface for concrete implementations of authentication policies
    BaseAuthorizationPolicy
        used as an interface for concrete implementations of authorization policies
    RequestContext
        contains data about the context of a request
    PolicyFactory
        the main class, used to apply policies
"""

from inuits_policy_based_auth.authentication.base_authentication_policy import (
    BaseAuthenticationPolicy,
)
from inuits_policy_based_auth.authorization.base_authorization_policy import (
    BaseAuthorizationPolicy,
)
from inuits_policy_based_auth.contexts import RequestContext
from inuits_policy_based_auth.policy_factory import PolicyFactory
