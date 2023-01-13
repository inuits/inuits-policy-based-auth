from flask import Flask, make_response
from flask_restful import Api, Resource


app = Flask(__name__)
api = Api(app)


class Entity(Resource):
    def get(self):
        return make_response("Welcome to inuits_policy_based_auth test API.", 200)


api.add_resource(Entity, "/")
