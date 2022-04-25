from os import access
from rest_framework.views import APIView
from .serializers import UserSerializer, LoginSerializer, VerifyOTPSerializers, LogoutSerializer, generate_access_token_using_refresh_token
from rest_framework.response import Response
from rest_framework import status
from .models import User
from authredis import serializers
from .services.custom_authentication import SafeJWTAuthentication
from rest_framework.permissions import IsAuthenticated
# Create your views here.


class UserAPI(APIView):
    """
        This class is used for registering user and get all users data.
    """
    # for registering the user

    def post(self, request):
        try:
            # set user data with key user or None to user info
            user_info = request.data.get("user", None)
            response_data = None
            if user_info:
                # converting data into complex model data type
                serializer = UserSerializer(data=user_info)
                if serializer.is_valid():
                    # save the data in database
                    serializer.save()
                    response_data = serializer.data
                else:
                    raise Exception("error: {}".
                                    format(serializer.error_messages))
     # if user is added successfully send the response with user data
            return Response({"message": "User is added suceessfully",
                            "data": response_data},
                            status=status.HTTP_406_NOT_ACCEPTABLE)

        except Exception as e:
            # send exception/error message
            return Response({"message": str(e),
                            "data": None},
                            status=status.HTTP_406_NOT_ACCEPTABLE)

    def get(self, request):
        try:
            query_set = User.objects.all()
            serializer = UserSerializer(query_set, many=True)
            response_data = None
            response_data = serializer.data
     # if user is added successfully send the response with user data
            return Response({"message": "User Details",
                            "data": response_data},
                            status=status.HTTP_202_ACCEPTED)

        except Exception as e:
            # send exception/error message
            return Response({"message": str(e),
                            "data": None},
                            status=status.HTTP_406_NOT_ACCEPTABLE)


class LoginAPI(APIView):
    def post(self, request):
        try:
            serializer = LoginSerializer()
            # getting access token and refresh token
            access_token, refresh_token = serializer.generate_token(
                email=request.data.get("email", None),
                password=request.data.get("password", None)
            )
            return Response(
                {"success": True,
                 "access_token": access_token,
                 "refresh_token": refresh_token,
                 }, status=status.HTTP_200_OK
            )
        except Exception as e:
            print(str(e))
            return Response(
                {"success": False,
                 "access_token": "",
                 "refresh_token": "",
                 }, status=status.HTTP_403_FORBIDDEN
            )


class VerifyOtp(APIView):
    authentication_classes = [SafeJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            serializer = VerifyOTPSerializers()
            otp = request.data.get("otp")
            user = request.user
            if not user:
                raise Exception("User is not present")
            is_verified = serializer.verify_otp(otp, user)
            if not is_verified:
                raise Exception("verification is failed")
            # getting access token and refresh token

            return Response(
                {"success": True,
                 "message": "Otp has verified"
                 }, status=status.HTTP_200_OK
            )
        except Exception as e:
            print(str(e))
            return Response(
                {"success": False,
                 "message": str(e)
                 }, status=status.HTTP_403_FORBIDDEN
            )

class Logout(APIView):
    authentication_classes = [SafeJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            serializer = LogoutSerializer()
            serializer.mark_token_as_black_listed(access_token=request.data["access_token"])
            # getting access token and refresh token

            return Response(
                {"success": True,
                 "message": "logout successfully !!"
                 }, status=status.HTTP_200_OK
            )
        except Exception as e:
            print(str(e))
            return Response(
                {"success": False,
                 "message": str(e)
                 }, status=status.HTTP_403_FORBIDDEN
            )

class RefreshAccessToken(APIView):
    authentication_classes = [SafeJWTAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            access_token = generate_access_token_using_refresh_token(request.user,
                                     request.data["refresh_token"])
            # getting access token and refresh token

            return Response(
                {"success": True,
                 "access_token": access_token,
                 }, status=status.HTTP_200_OK
            )
        except Exception as e:
            print(str(e))
            return Response(
                {"success": False,
                 "access_token": None
                 }, status=status.HTTP_403_FORBIDDEN
            )