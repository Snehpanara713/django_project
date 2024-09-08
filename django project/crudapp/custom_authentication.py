from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .utils import decode_custom_jwt_token
from .models import User  # Assuming your custom Admin model

class CustomJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]
        print(token,"ooooo")
        try:
            payload = decode_custom_jwt_token(token)
            print(payload,"llll")
            if payload is None:
                raise AuthenticationFailed('Invalid token: payload is None')

            # Debugging: Print the payload to see what's inside
            print("Decoded payload:", payload)

            # Validate token type for login authentication
            if payload.get('token_type') != 'reset_password':
                raise AuthenticationFailed('Invalid token type for login')
        except Exception as e:
            raise AuthenticationFailed('Invalid token')

        try:
            
            user = User.objects.get(pk=payload['user_id'])
            
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')

        # Ensure the user object is valid for your authentication requirements
        # if not user.is_active:
        #     raise AuthenticationFailed('User account is inactive')

        return (user, token)



class CustomJWTLoginAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]
        try:
            payload = decode_custom_jwt_token(token)
            if payload is None:
                raise AuthenticationFailed('Invalid token: payload is None')

            # Debugging: Print the payload to see what's inside
            print("Decoded payload:", payload)

            # Validate token type for login authentication
            if payload.get('token_type') != 'login':
                raise AuthenticationFailed('Invalid token type for login')
        except Exception as e:
            raise AuthenticationFailed('Invalid token')

        try:
            
            user = User.objects.get(pk=payload['user_id'])
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')

        # Ensure the user object is valid for your authentication requirements
        # if not user.is_active:
        #     raise AuthenticationFailed('User account is inactive')

        return (user, token)