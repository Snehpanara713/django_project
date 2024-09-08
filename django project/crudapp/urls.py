from django.urls import path

from .views import BookView, LoginAPI, RequestResetPassword, ResetPassword, UserAPI, VerifyCode

urlpatterns = [
    path('BookView/', BookView.as_view(), name='AdminRequestResetPassword'), 
    path('UserView/', UserAPI.as_view(), name='UserView'), 
    path('LoginAPI/', LoginAPI.as_view(), name='LoginAPI'), 
    path('request_reset_password/', RequestResetPassword.as_view(), name='request-reset-code'),
    path('verify_reset_code/', VerifyCode.as_view(), name='verify-reset-code'),
    path('reset_password/', ResetPassword.as_view(), name='reset-password'),
]