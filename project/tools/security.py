import base64
import hashlib
import calendar
import datetime

import jwt

from flask import current_app, abort



def __generate_password_digest(password: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=current_app.config["PWD_HASH_SALT"],
        iterations=current_app.config["PWD_HASH_ITERATIONS"],
    )


def generate_password_hash(password: str) -> str:
        return base64.b64encode(__generate_password_digest(password)).decode('utf-8')


def compare_password_hash(password_hash, other_password) -> bool:

    return password_hash == generate_password_hash(other_password)

    # decoded_digest = base64.b16decode(password_hash)
    # hash_digest = hashlib.pbkdf2_hmac(
    #     'sha256',
    #     other_password.encode('utf-8'),
    #     salt=current_app.config["PWD_HASH_SALT"],
    #     iterations=current_app.config["PWD_HASH_ITERATIONS"]
    # )
    # return hmac.compare_digest(decoded_digest, hash_digest)


class AuthService:
    def __init__(self, user_service):
        self.user_service = user_service

    @staticmethod
    def generate_tokens(user, password, is_refresh=False):

        if user is None:
            raise abort(404)

        if not is_refresh:
            if not compare_password_hash(user.password, password):
                abort(404)

        data = {
            "email": user.email,
            "password": user.password
        }

        # access token on 15 min
        min15 = datetime.datetime.utcnow() + datetime.timedelta(minutes=current_app.config['TOKEN_EXPIRE_MINUTES'])
        data["exp"] = calendar.timegm(min15.timetuple())
        access_token = jwt.encode(data, key=current_app.config['SECRET_KEY'],
                                  algorithm=current_app.config['ALGORITHM'])

        # refresh token on 130 day
        day130 = datetime.datetime.utcnow() + datetime.timedelta(days=current_app.config['TOKEN_EXPIRE_DAYS'])
        data["exp"] = calendar.timegm(day130.timetuple())
        refresh_token = jwt.encode(data, key=current_app.config['SECRET_KEY'],
                                   algorithm=current_app.config['ALGORITHM'])

        return {"access_token": access_token,
                "refresh_token": refresh_token}

    def approve_refresh_token(self, refresh_token):
        data = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALG])
        email = data['email']
        user = self.user_service.get_by_email(email)

        if not user:
            return False

        return self.generate_tokens(email, user.password, is_refresh=True)



