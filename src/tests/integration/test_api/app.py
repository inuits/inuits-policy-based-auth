from .policy_loader import load_policies
from flask import Flask, make_response
from flask_restful import Api, Resource, request
from inuits_policy_based_auth import PolicyFactory, RequestContext
from logging import Logger


app = Flask(__name__)
api = Api(app)

policy_factory = PolicyFactory()
load_policies(policy_factory, Logger(""))


class Entity(Resource):
    @policy_factory.apply_policies(
        RequestContext(request, ["read-entity", "update-entity"])
    )
    def get(self):
        user_context = policy_factory.get_user_context()
        response_body = {
            "auth_objects": user_context.auth_objects.get("token"),
            "email": user_context.email,
            "roles": user_context.roles,
            "scopes": user_context.scopes,
            "tenant_names": user_context.tenant_names,
            "tenant_objects": user_context.tenant_objects,
        }
        return make_response(response_body, 200)

    @policy_factory.apply_policies(RequestContext(request))
    def post(self):
        user_context = policy_factory.get_user_context()
        response_body = {
            "auth_objects": user_context.auth_objects.get("token"),
            "email": user_context.email,
            "roles": user_context.roles,
            "scopes": user_context.scopes,
            "tenant_names": user_context.tenant_names,
            "tenant_objects": user_context.tenant_objects,
        }
        return make_response(response_body, 201)

    @policy_factory.authenticate()
    def put(self):
        user_context = policy_factory.get_user_context()
        response_body = {
            "auth_objects": user_context.auth_objects.get("token"),
            "email": user_context.email,
            "roles": user_context.roles,
            "scopes": user_context.scopes,
            "tenant_names": user_context.tenant_names,
            "tenant_objects": user_context.tenant_objects,
        }
        return make_response(response_body, 200)


api.add_resource(Entity, "/")
