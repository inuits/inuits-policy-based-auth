"""
Module for securing API endpoints based on policies.

This module provides a generic and highly customizable way of securing
API endpoints based on policies using a simple decorator.
When dynamically loading policies from a custom configuration file, this
module will allow you to add new policies and override existing ones
to make it exactly fit your needs.

Classes
-------
    Authenticator
        used to authenticate a user
    BasePolicy
        used as an interface for concrete implementations of policies
    Context
        contains data about the context of a request
    PolicyFactory
        the main class, used to apply policies
    UserAuthData
        contains data about the authenticated user
"""


from inuits_policy_based_auth.authentication.authenticator import Authenticator
from inuits_policy_based_auth.authentication.user_auth_data import UserAuthData
from inuits_policy_based_auth.authorization.base_policy import BasePolicy
from inuits_policy_based_auth.authorization.context import Context
from inuits_policy_based_auth.authorization.policy_factory import PolicyFactory
