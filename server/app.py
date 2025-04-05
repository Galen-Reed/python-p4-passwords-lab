#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        user = User(
            username=json['username']
        )
        user.password_hash = json['password']
        db.session.add(user)
        db.session.commit()
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        # Get the user_id from the session
        user_id = session.get('user_id')

        # Check if the user_id exists in the session
        if user_id:
            user = User.query.filter(User.id == user_id).first()

            if user:
                return user.to_dict(), 200

        # If user is not logged in, return a 401 Unauthorized with a message
        return {}, 204  # Empty response with 204 status when not logged in

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            # Set the user_id in the session to maintain the user's login state
            session['user_id'] = user.id
            db.session.commit()  # Commit to ensure session data persists
            return user.to_dict(), 200  # Return user data as JSON
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        # Remove user_id from session to log out the user
        session.pop('user_id', None)  # This will remove the user_id key from the session, if it exists
        db.session.commit()  # Commit the session clear operation
        return {}, 204  # Return no content status

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
