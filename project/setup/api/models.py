from flask_restx import fields, Model

from project.setup.api import api

genre: Model = api.model('Жанр', {
    'id': fields.Integer(required=True, example=1),
    'name': fields.String(required=True, max_length=100, example='Комедия'),
})

director: Model = api.model('Режиссер', {
    'id': fields.Integer(required=True, example=1),
    'name': fields.String(required=True, max_length=100, example='Тейлор Шеридан'),
})

movie: Model = api.model('Фильм', {
    'id': fields.Integer(required=True, example=1),
    'title': fields.String(required=True, max_length=100, example='Йеллоустоун'),
    'description': fields.String(required=True, max_length=250,
                                 example='Владелец ранчо пытается сохранить землю своих предков. Кевин Костнер в неовестерне от автора «Ветреной реки»'),
    'trailer': fields.String(required=True, max_length=100, example='https://www.youtube.com/watch?v=UKei_d0cbP4'),
    'year': fields.Integer(required=True, example=2018),
    'rating': fields.Float(required=True, example=8.6),
    'genre': fields.Nested(genre),
    'director': fields.Nested(director),
})

user: Model = api.model('Пользователь', {
    'id': fields.Integer(required=True, example=1),
    'email': fields.String(required=True, max_length=100, example='mail@mail.ru'),
    'password': fields.String(required=True, max_length=250, example='123456'),
    'name': fields.String(required=False, max_length=100, example='Ivan'),
    'surname': fields.String(required=False, max_length=100, example='Ivanov'),
    'genre': fields.Nested(genre),
})
