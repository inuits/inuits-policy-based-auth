from .policy_loader import load_policies
from flask import Flask, make_response
from flask_restful import Api, Resource, request
from inuits_policy_based_auth import PolicyFactory, RequestContext
from inuits_policy_based_auth.helpers.tenant import Tenant
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
        if not user_context.x_tenant:
            user_context.x_tenant = Tenant()

        response_body = {
            "auth_objects": user_context.auth_objects.get("token"),
            "email": user_context.email,
            "roles": user_context.x_tenant.roles,
            "scopes": user_context.x_tenant.scopes,
        }
        return make_response(response_body, 200)

    @policy_factory.apply_policies(RequestContext(request))
    def post(self):
        user_context = policy_factory.get_user_context()
        if not user_context.x_tenant:
            user_context.x_tenant = Tenant()

        response_body = {
            "auth_objects": user_context.auth_objects.get("token"),
            "email": user_context.email,
            "roles": user_context.x_tenant.roles,
            "scopes": user_context.x_tenant.scopes,
        }
        return make_response(response_body, 201)

    @policy_factory.authenticate(RequestContext(request))
    def put(self):
        user_context = policy_factory.get_user_context()
        if not user_context.x_tenant:
            user_context.x_tenant = Tenant()

        response_body = {
            "auth_objects": user_context.auth_objects.get("token"),
            "email": user_context.email,
            "roles": user_context.x_tenant.roles,
            "scopes": user_context.x_tenant.scopes,
        }
        return make_response(response_body, 200)


api.add_resource(Entity, "/")
