from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import generics, status, viewsets
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .serializers import UserSerializer, ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer
from .models import User
import jwt, datetime

from .utils import Util
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.shortcuts import redirect

from django.http import HttpResponsePermanentRedirect

import os

class CustomRedirect(HttpResponsePermanentRedirect):

    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']

# Get All User
class UsersViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset =  User.objects.all()
    serializer_class = UserSerializer

# Register user.
class RegisterView(APIView):
    def post(self, request):
        # print(self)
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                    'error': None,
                    'data': serializer.data
                }, status=200)
        return Response({
                'error':{
                    'code' : 400,
                    'message': 'Email already exist!'
                },
                'data': None
            }, status=400)

# Login user.
class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            # raise AuthenticationFailed('User not found!')
            return Response({
                'error':{
                    'code' : 400,
                    'message': 'Email not found!'
                },
                'data': None
            }, status=400)

        if not user.check_password(password):
            # raise AuthenticationFailed('Incorrect password!')
            return Response({
                'error':{
                    'code' : 400,
                    'message': 'Incorrect Password!'
                },
                'data': None
            }, status=400)

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()

        response.set_cookie(key='authorizationToken', value=token, httponly=True)
        response.data = {
            'authorizationToken': token,
            'name': user.name,
            'email': user.email,
            'phone': user.phone
        }

        return response

# View user.
class UserView(APIView):

    def get(self, request):
        token = request.COOKIES.get('authorizationToken')

        if not token:
            # raise AuthenticationFailed('Unauthenticated!')
            return Response({
                'code' : 400,
                'message': 'authorizationToken not found!'
            }, status=400)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            # raise AuthenticationFailed('Unauthenticated!')
            return Response({
                'code' : 400,
                'message': 'authorizationToken expires!'
            }, status=400)

        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        # return Response(serializer.data)
        return Response({
            'code' : 200,
            'data': serializer.data
        }, status=200)

# Logout user.
class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('authorizationToken')
        response.data = {
            'status': True,
            'message': 'Logout Succesfully!'
        }
        return response

# Reset Password By User
class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)
            
        return Response({
            'code' : 200,
            'success': 'We have sent you a link to reset your password'
        }, status=status.HTTP_200_OK)

class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({
                    'code' : 400,
                    'error': 'Token is not valid, please request a new one'
                }, status=status.HTTP_400_BAD_REQUEST)

            response = Response()

            response.set_cookie(key='passwordToken', value=token, httponly=True)
            response.set_cookie(key='uidb64Token', value=uidb64, httponly=True)
            response.data = {
                'code': 200,
                'message': 'Credentials valid',
                'uidb64': uidb64, 
                'token': token
            }

            return response

            # return Response({
            #     'success': True,
            #     'message': 'Credentials valid','uidb64': uidb64, 'token': token
            # }, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({
                'code' : 400,
                'error': 'Token is not valid, please request a new one'
            }, status=status.HTTP_400_BAD_REQUEST)
   
class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        passwordToken = request.COOKIES.get('passwordToken')
        uidb64Token = request.COOKIES.get('uidb64Token')

        password = request.data['password']

        coy = { 
            'password': password, 
            'token': passwordToken, 
            'uidb64': uidb64Token
        }

        serializer = self.serializer_class(data=coy)
        serializer.is_valid(raise_exception=True)
        return Response({
            'code': 200, 
            'message': 'Password reset success'
        }, status=status.HTTP_200_OK)

# Reset Password Default
class RequestPasswordResetDefault(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)

            current_site = get_current_site(
                request=request).domain

            relativeLink = reverse(
                'password-default-confirm', kwargs={'uidb64': uidb64, 'token': token})

            absurl = 'http://'+current_site + relativeLink + '?email=' + email
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)
            
        return Response({
            'code' : 200,
            'success': 'We have sent you a link to reset your password'
        }, status=status.HTTP_200_OK)

class PasswordResetDefault(generics.GenericAPIView):
    
    serializer_class = SetNewPasswordSerializer
    serializer_classs = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        # email = 'yanda@jaringpangan.com'
        email = request.GET.get('email', '')

        print(email)

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({
                    'code' : 400,
                    'error': 'Token is not valid, please request a new one'
                }, status=status.HTTP_400_BAD_REQUEST)

            if User.objects.filter(id=id).exists():
                coy = { 
                    'password': '@Jawara2022', 
                    'token': token, 
                    'uidb64': uidb64
                }

                serializer = self.serializer_classs(data=coy)
                serializer.is_valid(raise_exception=True)

                email_body = 'Hello, \nUse link below to reset your password default @Jawara2022' 
                data = {'email_body': email_body, 'to_email': email,
                        'email_subject': 'Reset your passsword Successfully'}
                Util.send_email(data)
                
            return Response({
                'code' : 200,
                'success': 'We have sent you a password default to email'
            }, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({
                'code' : 400,
                'error': 'Token is not valid, please request a new one'
            }, status=status.HTTP_400_BAD_REQUEST)
