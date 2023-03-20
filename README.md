# inuits_policy_based_auth
inuits_policy_based_auth is a python package for securing API endpoints based on policies.

## Installation
Install inuits_policy_based_auth as follows:
```
pip install inuits-policy-based-auth
```

## Getting Started
In your app, instantiate the PolicyFactory by passing a logger as argument. For example, in app.py (all examples given are based on a Python Flask app).
```python
from inuits_policy_based_auth import PolicyFactory


policy_factory = PolicyFactory(logger)
```
### Manually loading policies
Importing and registering policies can be done manually.
```python
from inuits_policy_based_auth.authentication.policies.token_based_policies.authlib_flask_oauth2_policy import (
    AuthlibFlaskOauth2Policy,
)
from inuits_policy_based_auth.authorization.policies.super_admin_policy import (
    SuperAdminPolicy,
)


policy_factory.register_authentication_policy(AuthlibFlaskOauth2Policy(...))
policy_factory.register_authorization_policy(SuperAdminPolicy())
```
However, it is strongly recommended to load policies dynamically as this will allow you to make use of the full potential of this package.

### Dynamically loading policies
You can write a loader which loads policies dynamically based on a configuration file.

Example configuration file:
```json
{
  "[app_name]": {
    "name": "[app_name]",
    "description": "",
    "version": 0.1,
    "author": "Inuits",
    "author_email": "developers@inuits.eu",
    "license": "GPLv2",
    "policies": {
      "authentication": [
        "token_based_policies.authlib_flask_oauth2_policy"
      ],
      "authorization": [
        "super_admin_policy",
        "open_data_policy"
      ]
    }
  }
}
```

Example policy_loader.py:
```python
import json
import os

from importlib import import_module
from inuits_policy_based_auth import PolicyFactory
from inuits_policy_based_auth.exceptions import (
    PolicyFactoryException,
)


def load_policies(policy_factory: PolicyFactory):
    apps = {}

    configuration_file_name = os.getenv("CONFIGURATION_FILE_NAME") or ""
    with open(configuration_file_name) as configuration_file:
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
            os.getenv("ROLE_PERMISSION_FILE", "role_permission.json"),
            os.getenv("REMOTE_TOKEN_VALIDATION", False) in ["True", "true", True],
            os.getenv("REMOTE_PUBLIC_KEY", False),
        )

    return policy()
```

Now you can import the loader in app.py and pass ```policy_factory``` as an argument to it.
```python
from apps.policy_loader import load_policies


load_policies(policy_factory)
```
As you can see in these examples, dynamically loading policies will allow you to add new policies and override existing ones, which makes this package highly customizable and generic.

### Custom policies
Continuing from the examples above, you can make a custom authorization policy by creating a folder ```policies``` within a specific app. Here you should create the folders ```authentication``` and ```authorization``` that will contain custom policies which you can add to your configuration. In this case we name our new policy the same as an existing one, which will override it. Each authentication policy must inherit from BaseAuthenticationPolicy and implement the abstract method ```authenticate```, while each authorization policy must inherit from BaseAuthorizationPolicy and implement the abstract method ```authorize```.

Example folder structure:
```
api
├── apps
│  ├── [app_name]
│  │  ├── policies
│  │  │  ├── authentication
│  │  │  └── authorization
│  │  │     └── open_data_policy.py
│  │  ├── ...
...
│  ├── configuration.json
│  └── policy_loader.py
...
└── app.py
```

Example custom open_data_policy.py:
```python
from inuits_policy_based_auth import BaseAuthorizationPolicy


class OpenDataPolicy(BaseAuthorizationPolicy):
    def authorize(self, policy_context, user_context, request_context):
        request = request_context.http_request
        if request.method == "GET" and user_context.tenant == "inuits":
            policy_context.access_verdict = True

        return policy_context
```

## Usage
If everything is set up correctly, you can use the ```apply_policies``` decorator as follows:
```python
from app import policy_factory
from flask import request
from inuits_policy_based_auth import RequestContext


class Entity():
    @policy_factory.apply_policies(RequestContext(request))
    def get(self):
        ...
```

You can also use the ```authenticate``` decorator to only apply authentication policies:
```python
from app import policy_factory


class Entity():
    @policy_factory.authenticate()
    def get(self):
        ...
```

## Contributing
Do not hesitate to open issues and create pull requests.
