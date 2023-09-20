import os

from .. import flask_process
from .policy_loader import load_policies
from flask import Flask, make_response
from flask_restful import Api, Resource, request
from inuits_policy_based_auth import PolicyFactory, RequestContext
from logging import Logger


app = Flask(__name__)
api = Api(app)

policy_factory = PolicyFactory()
load_policies(policy_factory, Logger(""))


class GenericEndpoints(Resource):
    @policy_factory.authenticate(RequestContext(request))
    def get(self):
        user_context = policy_factory.get_user_context()
        (
            number_of_authenticate_calls,
            number_of_apply_policies_calls,
        ) = _get_number_of_decorator_calls()

        response_body = {
            "auth_objects": {
                "token": user_context.auth_objects.get("token"),
            },
            "email": user_context.email,
            "x_tenant": {
                "id": user_context.x_tenant.id,
                "roles": user_context.x_tenant.roles,
                "scopes": user_context.x_tenant.scopes,
                "raw": user_context.x_tenant.raw,
            },
            "bag": user_context.bag,
            "access_restrictions": {
                "filters": user_context.access_restrictions.filters
            },
            "number_of_authenticate_calls": number_of_authenticate_calls,
            "number_of_apply_policies_calls": number_of_apply_policies_calls,
            "request_context": {
                "generic_endpoint": {
                    "hash": hash(RequestContext(request)),
                    "serialized": str(RequestContext(request)._serialize()),
                }
            },
        }

        flask_process.clear_logs()
        return response_body

    @policy_factory.authenticate(RequestContext(request))
    def post(self):
        user_context = policy_factory.get_user_context()
        (
            number_of_authenticate_calls,
            number_of_apply_policies_calls,
        ) = _get_number_of_decorator_calls()

        response_body = {
            "auth_objects": {
                "token": user_context.auth_objects.get("token"),
            },
            "email": user_context.email,
            "x_tenant": {
                "id": user_context.x_tenant.id,
                "roles": user_context.x_tenant.roles,
                "scopes": user_context.x_tenant.scopes,
                "raw": user_context.x_tenant.raw,
            },
            "bag": user_context.bag,
            "access_restrictions": {
                "filters": user_context.access_restrictions.filters
            },
            "number_of_authenticate_calls": number_of_authenticate_calls,
            "number_of_apply_policies_calls": number_of_apply_policies_calls,
            "request_context": {
                "generic_endpoint": {
                    "hash": hash(RequestContext(request)),
                    "serialized": str(RequestContext(request)._serialize()),
                }
            },
        }

        flask_process.clear_logs()
        return response_body

    @policy_factory.authenticate(RequestContext(request))
    def put(self):
        user_context = policy_factory.get_user_context()
        (
            number_of_authenticate_calls,
            number_of_apply_policies_calls,
        ) = _get_number_of_decorator_calls()

        response_body = {
            "auth_objects": {
                "token": user_context.auth_objects.get("token"),
            },
            "email": user_context.email,
            "x_tenant": {
                "id": user_context.x_tenant.id,
                "roles": user_context.x_tenant.roles,
                "scopes": user_context.x_tenant.scopes,
                "raw": user_context.x_tenant.raw,
            },
            "bag": user_context.bag,
            "access_restrictions": {
                "filters": user_context.access_restrictions.filters
            },
            "number_of_authenticate_calls": number_of_authenticate_calls,
            "number_of_apply_policies_calls": number_of_apply_policies_calls,
            "request_context": {
                "generic_endpoint": {
                    "hash": hash(RequestContext(request)),
                    "serialized": str(RequestContext(request)._serialize()),
                }
            },
        }

        flask_process.clear_logs()
        return response_body


class ConcreteEndpoints(GenericEndpoints):
    @policy_factory.apply_policies(
        RequestContext(request, ["read-entity", "update-entity"])
    )
    def get(self):
        response_body = super().get()
        response_body["request_context"]["concrete_endpoint"] = {
            "hash": hash(RequestContext(request, ["read-entity", "update-entity"])),
            "serialized": str(
                RequestContext(request, ["read-entity", "update-entity"])._serialize()
            ),
        }
        return make_response(response_body, 200)

    @policy_factory.apply_policies(RequestContext(request))
    def post(self):
        response_body = super().post()
        response_body["request_context"]["concrete_endpoint"] = {
            "hash": hash(RequestContext(request)),
            "serialized": str(RequestContext(request)._serialize()),
        }
        return make_response(response_body, 201)

    @policy_factory.authenticate(RequestContext(request))
    def put(self):
        response_body = super().put()
        response_body["request_context"]["concrete_endpoint"] = {
            "hash": hash(RequestContext(request)),
            "serialized": str(RequestContext(request)._serialize()),
        }
        return make_response(response_body, 200)


def _get_number_of_decorator_calls() -> tuple[int, int]:
    number_of_authenticate_calls = 0
    number_of_apply_policies_calls = 0

    with open(str(os.getenv("TEST_API_LOGS")), "r") as logs:
        for line in logs:
            line = line.strip()
            if line == "authenticate":
                number_of_authenticate_calls += 1
            elif line == "apply_policies":
                number_of_apply_policies_calls += 1

    return number_of_authenticate_calls, number_of_apply_policies_calls


api.add_resource(ConcreteEndpoints, "/")
