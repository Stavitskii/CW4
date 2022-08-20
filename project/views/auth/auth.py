from flask_restx import Namespace, Resource

from flask import request
from project.container import user_service
from project.setup.api.models import user

api = Namespace('auth')


@api.route('/register')
class UsersRegisterView(Resource):

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


@api.route('/login')
class GenreView(Resource):
    @api.response(404, 'Not Found')
    @api.marshal_with(genre, code=200, description='OK')
    def get(self, genre_id: int):
        """
        Get genre by id.
        """
        return genre_service.get_item(genre_id)

