import json
import os

from importlib import import_module
from inuits_policy_based_auth import PolicyFactory
from inuits_policy_based_auth.exceptions import (
    PolicyFactoryException,
)
from logging import Logger


def load_policies(policy_factory: PolicyFactory, logger: Logger):
    apps = {}

    with open(str(os.getenv("TEST_API_CONFIGURATION")), "r") as configuration_file:
        apps = json.load(configuration_file)

    for app in apps:
        try:
            auth_type = "authentication"
            for policy_module_name in apps[app]["policies"].get(auth_type):
                policy = __get_class(app, auth_type, policy_module_name)
                policy = __instantiate_authentication_policy(
                    policy_module_name, policy, logger
                )
                policy_factory.register_authentication_policy(
                    f"tests.integration.{app}", policy
                )

            auth_type = "authorization"
            for policy_module_name in apps[app]["policies"].get(auth_type):
                policy = __get_class(app, auth_type, policy_module_name)
                policy_factory.register_authorization_policy(
                    f"tests.integration.{app}", policy()
                )
        except Exception as error:
            raise PolicyFactoryException(
                f"Policy factory was not configured correctly: {str(error)}"
            ).with_traceback(error.__traceback__)

    policy_factory.set_fallback_key_for_policy_mapping("tests.integration.test_api")


def __get_class(app, auth_type, policy_module_name):
    locations = [
        policy_module_name,
        f"apps.{app}.policies.{auth_type}.{policy_module_name}",
        f"inuits_policy_based_auth.{auth_type}.policies.{policy_module_name}",
    ]
    for location in locations:
        try:
            module = import_module(location)
            break
        except ModuleNotFoundError:
            pass
    else:
        raise ModuleNotFoundError(f"Policy {policy_module_name} not found")

    policy_class_name = module.__name__.split(".")[-1].title().replace("_", "")
    policy = getattr(module, policy_class_name)
    return policy


def __instantiate_authentication_policy(policy_module_name, policy, logger: Logger):
    token_schema = __load_token_schema()

    if policy_module_name == "token_based_policies.authlib_flask_oauth2_policy":
        allow_anonymous_users = (
            True
            if os.getenv("ALLOW_ANONYMOUS_USERS", "false").lower() == "true"
            else False
        )
        return policy(
            logger,
            token_schema,
            os.getenv("STATIC_ISSUER"),
            os.getenv("STATIC_PUBLIC_KEY"),
            os.getenv("ALLOWED_ISSUERS"),
            allow_anonymous_users,
        )
    if policy_module_name == "token_based_policies.tenant_token_roles_policy":
        return policy(
            token_schema,
            os.getenv("ROLE_SCOPE_MAPPING", os.getenv("TEST_API_SCOPES")),
            (
                True
                if os.getenv("ALLOW_ANONYMOUS_USERS", "false").lower() == "true"
                else False
            ),
        )

    return policy()


def __load_token_schema() -> dict:
    token_schema_path = os.getenv(
        "TEST_API_TOKEN_SCHEMA", "src/tests/integration/test_api/token_schema.json"
    )
    with open(token_schema_path, "r") as token_schema:
        return json.load(token_schema)
