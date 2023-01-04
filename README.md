# inuits-policy-based-auth
inuits_policy_based_auth is a python package for securing API endpoints based on policies.

## Installation
Install inuits_policy_based_auth as follows:
```
pip install inuits-policy-based-auth
```

## Getting Started
In your app, instantiate the PolicyFactory by passing the Authenticator and a logger as arguments. For example, in app.py (all examples given are based on a Python Flask app).
```
policy_factory = PolicyFactory(Authenticator(), logger)
```
### Manually loading policies
Importing and registering policies can be done manually.
```
from inuits_policy_based_auth.authentication.strategies.token_strategy.authlib_flask_oauth2_strategy import AuthlibFlaskOauth2Strategy
from inuits_policy_based_auth.authorization.policies.super_admin_policy import SuperAdminPolicy


policy_factory.authenticator.strategy = AuthlibFlaskOauth2Strategy(...)
policy_factory.register(SuperAdminPolicy())
```
However, it is strongly recommended to load policies dynamically as this will allow you to make use of the full potential of this package.

### Dynamically loading policies
You can write a loader which can load policies dynamically based on a configuration file.

Example configuration file:
```
{
  "[app_name]": {
    "name": "[app_name]",
    "description": "",
    "version": 0.1,
    "author": "Inuits",
    "author_email": "developers@inuits.eu",
    "license": "GPLv2",
    "security": {
      "authentication_strategy": "token_strategy.authlib_flask_oauth2_strategy",
      "policies": [
        "open_data_policy",
        "super_admin_policy"
      ]
    }
  }
}
```

Example loader.py:
```
import os
import util

from importlib import import_module
from inuits_policy_based_auth.authorization.policy_factory import PolicyFactory
from inuits_policy_based_auth.inuits_policy_based_auth_exceptions import (
    PolicyFactoryException,
)


def load_policies(policy_factory: PolicyFactory):
    apps = util.read_json_as_dict(os.getenv("APPS_MANIFEST"))
    for app in apps:
        try:
            authentication_strategy = apps[app]["security"].get(
                "authentication_strategy"
            )
            strategy = __instantiate_authentication_strategy(
                app, authentication_strategy, policy_factory
            )
            policy_factory.authenticator.strategy = strategy

            for policy in apps[app]["security"].get("policies"):
                policy_class = __get_module_class(app, policy=policy)
                policy_factory.register(policy_class())
        except Exception as error:
            raise PolicyFactoryException(
                f"Policy factory was not correctly configured: {str(error)}"
            ).with_traceback(error.__traceback__)


def __instantiate_authentication_strategy(
    app, authentication_strategy, policy_factory: PolicyFactory
):
    strategy_class = __get_module_class(
        app, authentication_strategy=authentication_strategy
    )

    if authentication_strategy == "token_strategy.authlib_flask_oauth2_strategy":
        return strategy_class(
            policy_factory.logger,
            os.getenv("STATIC_ISSUER", False),
            os.getenv("STATIC_PUBLIC_KEY", False),
            os.getenv("REALMS", "").split(","),
            os.getenv("ROLE_PERMISSION_FILE", "role_permission.json"),
            os.getenv("REMOTE_TOKEN_VALIDATION", False) in ["True", "true", True],
            os.getenv("REMOTE_PUBLIC_KEY", False),
        )

    return strategy_class()


def __get_module_class(app, *, authentication_strategy=None, policy=None):
    module = None
    if authentication_strategy and not policy:
        module = import_module(
            f"inuits_policy_based_auth.authentication.strategies.{authentication_strategy}"
        )
    elif policy and not authentication_strategy:
        try:
            module = import_module(f"apps.{app}.policies.{policy}")
        except:
            module = import_module(
                f"inuits_policy_based_auth.authorization.policies.{policy}"
            )
    else:
        raise PolicyFactoryException(
            "Missing keys in app_list.json under '{app}.security'."
        )

    module_class_name = module.__name__.split(".")[-1].title().replace("_", "")
    module_class = getattr(module, module_class_name)
    return module_class
```

Now you can import the loader in app.py and pass ```policy_factory``` as an argument to it.
```
load_policies(policy_factory)
```
As you can see in these examples, dynamically loading policies will allow you to add new policies and override existing ones, which makes this package highly customizable and generic.

### Custom policies
Continuing from the examples above, you can make a custom policy by creating a folder ```policies``` within a specific app. Here you can create a policy which you can add to your configuration. In this case we name our new policy the same as an existing one, which will override it. Each policy must inherit from BasePolicy and implement the abstract methods ```authenticate``` and ```authorize```.

Example folder structure:
```
api
├── apps
│  ├── [app_name]
│  │  ├── policies
│  │  │  └── open_data_policy.py
│  │  ├── ...
...
│  ├── app_list.json
│  └── loader.py
...
└── app.py
```

Example custom open_data_policy.py:
```
from inuits_policy_based_auth.authorization.base_policy import BasePolicy
from werkzeug.exceptions import Forbidden


class OpenDataPolicy(BasePolicy):
    def authenticate(self, authenticator, context):
        return authenticator.authenticate()

    def authorize(self, user_auth_data, context):
        request = context.http_request
        if request.method != "GET":
            raise Forbidden()
```

## Bugs and Feature requests
**Warning!**

This package is in early stages of development and will require a few more iterations to be considered stable. As of right now, the PolicyFactory cannot handle conflicting policies, which may result in unauthorized access.

## Contributing
Do not hesitate to open issues and create pull requests.
