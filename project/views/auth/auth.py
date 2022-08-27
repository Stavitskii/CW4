from flask_restx import Namespace, Resource

from flask import request
from project.container import user_service
from project.setup.api.models import user

api = Namespace('auth')


@api.route('/register/')
class RegisterView(Resource):

    @api.marshal_with(user, as_list=True, code=200, description='OK')
    def post(self):
        """
        Register user
        """
        data = request.json
        if data.get('email') and data.get('password'):
            return user_service.create_user(data.get('email'), data.get('password')), 201
        else:
            return "Email or password needed", 401


@api.route('/login/')
class LoginView(Resource):
    @api.response(404, 'Not Found')
    #@api.marshal_with(user, code=200, description='OK')
    def post(self):
        data = request.json
        if data.get('email') and data.get('password'):
            return user_service.check(data.get('email'), data.get('password')), 201
        else:
            return "Email or password needed", 401

    @api.response(404, 'Not Found')
    def put(self):
        data = request.json
        if data.get('access_token') and data.get('refresh_token'):
            return user_service.update_token(data.get('refresh_token')), 201
        else:
            return "Something needed", 401

