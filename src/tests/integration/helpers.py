import json
import os


def get_payload(roles):
    return {
        "azp": "inuits-policy-based-auth",
        "resource_access": {"inuits-policy-based-auth": {"roles": roles}},
    }


def get_scopes(role):
    with open(str(os.getenv("TEST_API_SCOPES")), "r") as scopes_file:
        return json.load(scopes_file)[role]
