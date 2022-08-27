from importlib.resources import Resource

from flask import request
from flask_restx import Namespace

from project.container import user_service
from project.setup.api.models import user

api = Namespace('user')


@api.route('/')
class RegisterView(Resource):
    @api.marshal_with(user, as_list=True, code=200, description='OK')
    def patch(self):
        data = request.json
        header = request.headers
        return user_service.update_user(data=data, refresh_token=header)



    @api.marshal_with(user, as_list=True, code=200, description='OK')
    def get(self):
        data = request.json
        header = request.headers
        return user_service.get_user_by_token(refresh_token=header)





# @api.route('/password/')
# class LoginView(Resource):
#     @api.response(404, 'Not Found')
#     # @api.marshal_with(user, code=200, description='OK')
#     def post(self):
#         data = request.json
#         if data.get('email') and data.get('password'):
#             return user_service.check(data.get('email'), data.get('password')), 201
#         else:
#             return "Email or password needed", 401
