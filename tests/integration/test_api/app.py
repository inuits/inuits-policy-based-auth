from .policy_loader import load_policies
from flask import Flask, make_response
from flask_restful import Api, Resource, request
from inuits_policy_based_auth import PolicyFactory, RequestContext
from logging import Logger


app = Flask(__name__)
api = Api(app)

policy_factory = PolicyFactory(Logger(""))
load_policies(policy_factory)


class Entity(Resource):
    @policy_factory.apply_policies(RequestContext(request))
    def get(self):
        return make_response("Welcome to inuits_policy_based_auth test API.", 200)


api.add_resource(Entity, "/")
