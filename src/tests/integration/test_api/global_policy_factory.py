from flask import g
from inuits_policy_based_auth import PolicyFactory, RequestContext


def apply_policies(request_context: RequestContext):
    global _policy_factory
    return _policy_factory.apply_policies(request_context)


def authenticate(request_context: RequestContext):
    global _policy_factory
    return _policy_factory.authenticate(request_context)


def get_user_context():
    return g.get("user_context")


def user_context_setter(user_context):
    g.user_context = user_context


_policy_factory = PolicyFactory(user_context_setter)
