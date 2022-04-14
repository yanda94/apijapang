from django.urls import path
from .views import RegisterView, LoginView, UserView, LogoutView,  RequestPasswordResetEmail, SetNewPasswordAPIView, PasswordTokenCheckAPI, RequestPasswordResetDefault, PasswordResetDefault

urlpatterns = [
     path('register', RegisterView.as_view()),
     path('login', LoginView.as_view()),
     path('user', UserView.as_view()),
     path('logout', LogoutView.as_view()),
     
     path('request-reset-email/', RequestPasswordResetEmail.as_view(),
          name="request-reset-email"),
     path('password-reset/<uidb64>/<token>/',
          PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
     path('password-reset-complete', SetNewPasswordAPIView.as_view(),
          name='password-reset-complete'),

     path('request-password-default/', RequestPasswordResetDefault.as_view(),
          name="request-password-default"),
     path('password-default/<uidb64>/<token>/',
          PasswordResetDefault.as_view(), name='password-default-confirm'),
]
