#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup',
        'login',
        'check_session'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        result = make_response(
            {'error': '401 Unauthorized'},
            401
        )

        return result

class Signup(Resource):
    def post(self):
        fields = request.get_json()

        username = fields.get('username')
        password = fields.get('password')
        image_url = fields.get('image_url')
        bio = fields.get('bio')

        new_user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )

        new_user.password_hash = password

        try:
            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id

            result = make_response(
                new_user.to_dict(),
                201
            )

            return result

        except IntegrityError:
            result = make_response(
                {'error': '422 Unprocessable Entity'},
                422
            )

            return result

class CheckSession(Resource):
    def get(self):
        user_id = session['user_id']
        if user_id:
            user = User.query.filter(User.id == user_id).first()

            result = make_response(
                user.to_dict(),
                200
            )

        else:
            result = make_response(
                {},
                401
            )

        return result

class Login(Resource):
    def post(self):

        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id

            result = make_response(
                user.to_dict(),
                200
            )

        else:
            result = make_response(
                {'error': '401 Unauthorized'},
                401
            )

        return result

class Logout(Resource):
    def delete(self):

        session['user_id'] = None

        result = make_response(
            {},
            204
        )

        return result

class RecipeIndex(Resource):
    def get(self):
        if 'user_id' not in session:
            result = make_response(
                {'error': 'Unauthorized'},
                401
            )
            return result

        user = User.query.filter(User.id == session['user_id']).first()

        result = make_response(
            [recipe.to_dict() for recipe in user.recipes],
            200
        )

        return result

    def post(self):
        fields = request.get_json()

        title = fields['title']
        instructions = fields['instructions']
        minutes_to_complete = fields['minutes_to_complete']

        try:
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id']
            )

            db.session.add(new_recipe)
            db.session.commit()

            result = make_response(
                new_recipe.to_dict(),
                201
            )

            return result

        except ValueError as e:
            result = make_response(
                {'error': str(e)},
                422
            )

            return result

        except IntegrityError:
            result = make_response(
                {'error': '422 Unprocessable Entity'},
                422
            )

            return result

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)