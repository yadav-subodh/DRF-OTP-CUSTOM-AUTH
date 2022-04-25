from datetime import datetime
from rest_framework import serializers, exceptions
from .models import User
from .services.token import generate_access_token, generate_refresh_token
from random import randint
from .services.mail import send_mail_to_authenticate
from django.conf import settings
import json
from .services.redis_connection import connection_object
import jwt
# create user serializer


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["firstName", "lastName", "dateOfBirth", "email",
                  "is_staff", "is_active", "createdAt", "uid", "updatedAt"]


class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["uid", "firstName", "lastName", "email"]

    def generate_token(self, email, password):
        # check email and password must not be None
        if (email is None) or (password is None):
            raise exceptions.AuthenticationFailed(
                'email and password required')
        # fetch data from db
        user = User.objects.filter(email=email).first()
        if(user is None):
            raise exceptions.AuthenticationFailed('user not found')
        if (not user.check_password(password)):
            raise exceptions.AuthenticationFailed('wrong password')
        # if email and password is correct, generate tokens
        access_token = generate_access_token(user)
        refresh_token = generate_refresh_token(user)
        # generate otp of six digit
        otp = randint(100000, 999999)
        # send otp by mail to authenticated user
        subject = 'welcome to kaido'
        message = f'Hi {user.firstName}, Welcome to kaido.\n OTP for login at Kaido is: {otp}\n , Don\'t disclose to anyone.'
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [user.email, ]

        try:
            send_mail_to_authenticate(
                subject, message, email_from, recipient_list)
        except Exception as e:
            raise Exception(str(e))
        # creating data set to login with multiple otp
        otp_data = connection_object.get(user.uid)
        data_to_store = {}
        if otp_data:
            otp_data = json.loads(otp_data)
            data_to_store = otp_data
        data_to_store[otp] = str(datetime.now())
        connection_object.set(user.uid, json.dumps(data_to_store))
        return access_token, refresh_token


class VerifyOTPSerializers(serializers.Serializer):
    def verify_otp(self, otp, user):
        otp_data = connection_object.get(user.uid)
        sent_otp_date_time_str = json.loads(otp_data).get(str(otp))
        print(sent_otp_date_time_str)
        if not sent_otp_date_time_str:
            raise Exception("invalid otp")
        sent_otp_time = datetime.strptime(
            sent_otp_date_time_str, '%Y-%m-%d %H:%M:%S.%f')
        current_time = datetime.now()
        time_difference = current_time-sent_otp_time
        # converting time difference in minute
        time_diff_in_minutes = int(
            round(time_difference.total_seconds()/60, 0))
        # otp is valid only for 20 minutes
        if time_diff_in_minutes > 20:
            raise Exception("time validity has expired, please login again")
        return True


class LogoutSerializer():
    def mark_token_as_black_listed(self, access_token):
        try:
            token_data = connection_object.get("blackListedToken")
            token_to_store = {}
            if token_data:
                token_data = json.loads(token_data)
                token_to_store = token_data
            token_to_store[access_token] = True
            connection_object.set("blackListedToken", json.dumps(token_to_store))

        except Exception as e:
            print(str(e))
            raise Exception("token can't be blacklisted")

def generate_access_token_using_refresh_token(user, refresh_token):
    try:
        payload = jwt.decode(
            refresh_token, settings.REFRESH_TOKEN_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise exceptions.AuthenticationFailed(
            'refresh token has expired, please login again.')
    return generate_access_token(user)