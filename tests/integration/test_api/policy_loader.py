import json
import os

from importlib import import_module
from inuits_policy_based_auth import PolicyFactory
from inuits_policy_based_auth.exceptions import (
    PolicyFactoryException,
)


def load_policies(policy_factory: PolicyFactory):
    apps = {}

    with open(str(os.getenv("TEST_API_CONFIGURATION")), "r") as configuration_file:
        apps = json.load(configuration_file)

    for app in apps:
        try:
            auth_type = "authentication"
            for policy_module_name in apps[app]["policies"].get(auth_type):
                policy = __get_class(app, auth_type, policy_module_name)
                policy = __instantiate_authentication_policy(
                    policy_module_name, policy, policy_factory.logger
                )
                policy_factory.register_authentication_policy(policy)

            auth_type = "authorization"
            for policy_module_name in apps[app]["policies"].get(auth_type):
                policy = __get_class(app, auth_type, policy_module_name)
                policy_factory.register_authorization_policy(policy())
        except Exception as error:
            raise PolicyFactoryException(
                f"Policy factory was not configured correctly: {str(error)}"
            ).with_traceback(error.__traceback__)


def __get_class(app, auth_type, policy_module_name):
    module = None

    try:
        module = import_module(f"apps.{app}.policies.{auth_type}.{policy_module_name}")
    except:
        module = import_module(
            f"inuits_policy_based_auth.{auth_type}.policies.{policy_module_name}"
        )

    policy_class_name = module.__name__.split(".")[-1].title().replace("_", "")
    policy = getattr(module, policy_class_name)
    return policy


def __instantiate_authentication_policy(policy_module_name, policy, logger):
    if policy_module_name == "token_based_policies.authlib_flask_oauth2_policy":
        return policy(
            logger,
            os.getenv("STATIC_ISSUER", False),
            os.getenv("STATIC_PUBLIC_KEY", False),
            os.getenv("REALMS", "").split(","),
            os.getenv("ROLE_PERMISSION_FILE", os.getenv("TEST_API_SCOPES")),
            os.getenv("REMOTE_TOKEN_VALIDATION", False) in ["True", "true", True],
            os.getenv("REMOTE_PUBLIC_KEY", False),
        )

    return policy()
