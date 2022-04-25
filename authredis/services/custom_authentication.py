import jwt
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.conf import settings
from django.contrib.auth import get_user_model
from .redis_connection import connection_object
import json


class SafeJWTAuthentication(BaseAuthentication):

    def authenticate(self, request):
        User = get_user_model()
        authorization_heaader = request.headers.get('Authorization')

        if not authorization_heaader:
            return None
        try:
            access_token = authorization_heaader.split(' ')[1]
            # checking, is token listed in black_list
            print("connection object=>", connection_object)
            black_listed_token = connection_object.get("blackListedToken")
            if black_listed_token:
                black_listed_token = json.loads(black_listed_token)
                if black_listed_token.get(access_token):
                    raise exceptions.AuthenticationFailed(
                        "Token is black listed, please login again")
            payload = jwt.decode(
                access_token, settings.SECRET_KEY, algorithms=['HS256'])

        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('access_token expired')
        except IndexError:
            raise exceptions.AuthenticationFailed('Token prefix missing')

        user = User.objects.filter(id=payload['user_id']).first()
        if user is None:
            raise exceptions.AuthenticationFailed('User not found')

        if not user.is_active:
            raise exceptions.AuthenticationFailed('user is inactive')
        return (user, None)
