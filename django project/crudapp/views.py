from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from crud_operation import settings
from crudapp.custom_authentication import CustomJWTLoginAuthentication
from crudapp.utils import create_custom_jwt_token_for_login
from .models import Book, User
from .serializers import BookSerializer, EmailSerializer, PasswordResetSerializer, UserSerializer
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from django.core.paginator import Paginator, EmptyPage
from django.db.models import Q
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
from datetime import datetime, timedelta
from rest_framework.exceptions import AuthenticationFailed
# from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import BaseAuthentication

from django.utils import timezone
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string


# JWT_SECRET = settings.SECRET_KEY
# JWT_ALGORITHM = 'HS256'
# ACCESS_TOKEN_EXPIRY = 15 
# REFRESH_TOKEN_EXPIRY = 60 

# class TokenAuthentication(BaseAuthentication):
#     def authenticate(self, request):
#         # token = request.headers.get('Authorization', '').split('Bearer ')[-1]
#         token = request.headers.get('Authorization', '') 
#         if not token:
#             return None  # Return None if no token is provided

#         try:
#             # Decode the token
#             payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            
#             # if not payload:
#             #     raise AuthenticationFailed('Invalid token payload.')
#             # print(payload)
#             user_id = payload['user_id']
#             # Here, you should fetch the user object using user_id
#             # For example, assuming you have a User model:
#             # user = User.objects.get(id=user_id)
#             user = User.objects.get(pk=user_id)  # Implement this method to fetch user

#         except jwt.ExpiredSignatureError:
#             raise AuthenticationFailed('Token has expired.')
#         except jwt.InvalidTokenError:
#             raise AuthenticationFailed('Invalid token.')
#         except User.DoesNotExist:
#             raise AuthenticationFailed('No user matching this token was found.')

#         return (user, None)  # Return a tuple of (user, token)

#     def get_user(self, user_id):
#         # Implement your logic to fetch and return the user object based on user_id
#         # For example:
#         from .models import User  # Replace with your actual User model
#         return User.objects.get(user_id=user_id)
    
#     def decode_custom_jwt_token(token):
#         try:
#             payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
#             return payload
#         except jwt.ExpiredSignatureError:
#             return None
#         except jwt.InvalidTokenError:
#             return None
    

# Create your views here.
class BookView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    # permission_classes = [AllowAny]
    authentication_classes = [CustomJWTLoginAuthentication]

    @swagger_auto_schema(
        tags=['Book'],
        manual_parameters=[
            openapi.Parameter('title', openapi.IN_FORM, type=openapi.TYPE_STRING, description='Title of the book', required=False),
            openapi.Parameter('author', openapi.IN_FORM, type=openapi.TYPE_STRING, description='Author of the book', required=False),
            openapi.Parameter('isbn', openapi.IN_FORM, type=openapi.TYPE_STRING, description='ISBN of the book', required=False),
            openapi.Parameter('pages', openapi.IN_FORM, type=openapi.TYPE_INTEGER, description='Number of pages in the book', required=False),
        ],
        # request_body=BookSerializer,
        responses={
            200: openapi.Response('Success', BookSerializer(many=True)),
            201: openapi.Response('Book Created Successfully', BookSerializer),
            400: openapi.Response('Bad Request', examples={"application/json": {"status": "fail", "message": "Validation errors"}}),
            404: openapi.Response('Not Found', examples={"application/json": {"status": "fail", "message": "Book not found"}}),
            500: openapi.Response('Internal Server Error', examples={"application/json": {"status": "error", "message": "Error message"}})
        },
        security=[{'Bearer': []}]
    )
    def post(self, request):
        serializer = BookSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        tags=['Book'],
        manual_parameters=[
            openapi.Parameter('book_id', openapi.IN_FORM, type=openapi.TYPE_INTEGER, description='ID of the book to update', required=True),
            openapi.Parameter('title', openapi.IN_FORM, type=openapi.TYPE_STRING, description='Title of the book', required=False),
            openapi.Parameter('author', openapi.IN_FORM, type=openapi.TYPE_STRING, description='Author of the book', required=False),
            openapi.Parameter('isbn', openapi.IN_FORM, type=openapi.TYPE_STRING, description='ISBN of the book', required=False),
            openapi.Parameter('pages', openapi.IN_FORM, type=openapi.TYPE_INTEGER, description='Number of pages in the book', required=False),
        ],
        request_body=BookSerializer,
        responses={
            200: openapi.Response('Success', BookSerializer),
            400: openapi.Response('Bad Request', examples={"application/json": {"status": "fail", "message": "Validation errors"}}),
            404: openapi.Response('Not Found', examples={"application/json": {"status": "fail", "message": "Book not found"}}),
            500: openapi.Response('Internal Server Error', examples={"application/json": {"status": "error", "message": "Error message"}})
        },
        security=[{'Bearer': []}]
    )
    def put(self, request):
        book_id = request.data.get('book_id')
        if not book_id:
            return Response({
                'status': 'fail',
                'message': 'Book ID is required.'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            book = Book.objects.get(book_id=book_id)
        except Book.DoesNotExist:
            return Response({
                'status': 'fail',
                'message': 'Book not found.',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = BookSerializer(book, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'status': 'success',
                'message': 'Book updated successfully',
                'data': serializer.data
            }, status=status.HTTP_200_OK)

        return Response({
            'status': 'fail',
            'message': 'Validation errors',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        tags=['Book'],
        manual_parameters=[
            openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description='Number of items per page', required=False, default=10),
            openapi.Parameter('page_number', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description='Page number', required=False, default=1),
            openapi.Parameter('book_id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description='ID of the book to filter by', required=False),
            openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING, description='Search query for filtering books', required=False),
        ],
        responses={
            200: openapi.Response('Success', BookSerializer(many=True)),
            400: openapi.Response('Bad Request', examples={"application/json": {"status": "fail", "message": "Validation errors"}}),
            404: openapi.Response('Not Found', examples={"application/json": {"status": "fail", "message": "Page not found"}}),
            500: openapi.Response('Internal Server Error', examples={"application/json": {"status": "error", "message": "Error message"}})
        }
    )
    def get(self, request):
        try:
            page_size = int(request.query_params.get('page_size', 10))
            page_number = int(request.query_params.get('page_number', 1))
            book_id = request.query_params.get('book_id')
            search_query = request.query_params.get('search')

            # Start with a base queryset
            queryset = Book.objects.all()

            if book_id:
                # If book_id is provided, get a single book instance
                book = queryset.filter(book_id=book_id).first()
                if not book:
                    return Response({
                        'status': 'fail',
                        'message': 'Book not found.',
                        'data': {}
                    }, status=status.HTTP_404_NOT_FOUND)

                # Serialize and return the single book instance
                serializer = BookSerializer(book)
                return Response({
                    'status': 'success',
                    'message': 'Book retrieved successfully',
                    'data': serializer.data
                }, status=status.HTTP_200_OK)

            if search_query:
                queryset = queryset.filter(
                    Q(title__icontains=search_query) |
                    Q(author__icontains=search_query) |
                    Q(isbn__icontains=search_query)
                )

            # Apply pagination to the queryset
            paginator = Paginator(queryset, page_size)
            try:
                page_obj = paginator.page(page_number)
            except EmptyPage:
                return Response({
                    'status': 'fail',
                    'message': 'Page not found.',
                    'data': {}
                }, status=status.HTTP_404_NOT_FOUND)

            # Serialize the paginated queryset
            serializer = BookSerializer(page_obj.object_list, many=True, context={'request': request})

            response_data = {
                'total_pages': paginator.num_pages,
                'current_page': page_obj.number,
                'total_items': paginator.count,
                'results': serializer.data
            }

            return Response({
                'status': 'success',
                'message': 'Books retrieved successfully',
                'data': response_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    @swagger_auto_schema(
        tags=['Book'],
        manual_parameters=[
            openapi.Parameter('book_id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, description='ID of the book to delete', required=True),
        ],
        responses={
            200: openapi.Response('Success', examples={"application/json": {"status": "success", "message": "Book deleted successfully"}}),
            400: openapi.Response('Bad Request', examples={"application/json": {"status": "fail", "message": "Book ID is required"}}),
            404: openapi.Response('Not Found', examples={"application/json": {"status": "fail", "message": "Book not found"}}),
            500: openapi.Response('Internal Server Error', examples={"application/json": {"status": "error", "message": "Error message"}})
        }
    )
    def delete(self, request):
        book_id = request.query_params.get('book_id')
        if not book_id:
            return Response({
                'status': 'fail',
                'message': 'Book ID is required.'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            book = Book.objects.get(book_id=book_id)
            book.delete()
            return Response({
                'status': 'success',
                'message': 'Book deleted successfully'
            }, status=status.HTTP_200_OK)

        except Book.DoesNotExist:
            return Response({
                'status': 'fail',
                'message': 'Book not found.'
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
            
class UserAPI(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        tags=['User'],
        manual_parameters=[
            openapi.Parameter('mobile_no', openapi.IN_FORM, type=openapi.TYPE_STRING, description='Mobile number of the user', required=True),
            openapi.Parameter('firstname', openapi.IN_FORM, type=openapi.TYPE_STRING, description='First name of the user', required=True),
            openapi.Parameter('lastname', openapi.IN_FORM, type=openapi.TYPE_STRING, description='Last name of the user', required=True),
            openapi.Parameter('email_id', openapi.IN_FORM, type=openapi.TYPE_STRING, description='Email ID of the user', required=True),
            openapi.Parameter('password', openapi.IN_FORM, type=openapi.TYPE_STRING, description='Password of the user', required=True),
        ],
        request_body=UserSerializer,
        responses={
            201: openapi.Response('User Created Successfully', UserSerializer),
            400: openapi.Response('Bad Request', examples={"application/json": {"status": "fail", "message": "Validation errors"}}),
            500: openapi.Response('Internal Server Error', examples={"application/json": {"status": "error", "message": "Error message"}})
        },
        security=[{'Bearer': []}]
    )
    
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save() 
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    

    
class LoginAPI(APIView):
    permission_classes = [AllowAny]  # Allow non-authenticated users to access this view
    parser_classes = (MultiPartParser, FormParser)

    @swagger_auto_schema(
        tags=['User'],
        manual_parameters=[
            openapi.Parameter('email_id', openapi.IN_FORM, type=openapi.TYPE_STRING, description='Email ID of the user', required=True),
            openapi.Parameter('password', openapi.IN_FORM, type=openapi.TYPE_STRING, description='Password of the user', required=True),
        ],
        responses={
            200: openapi.Response('Login Successful', examples={"application/json": {"access": "access_token", "refresh": "refresh_token"}}),
            400: openapi.Response('Bad Request', examples={"application/json": {"status": "fail", "message": "Invalid credentials"}}),
        }
    )
    def post(self, request):
        email_id = request.data.get('email_id')
        password = request.data.get('password')
        
        # Ensure email and password are provided
        if not email_id or not password:
            return Response({'status': 'error', 'message': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Fetch the user using the email_id
            user = User.objects.get(email_id=email_id)
            
            
            if check_password(password, user.password):
              
                token = create_custom_jwt_token_for_login(user)
                
           
                response_data = {
                    'status': 'success',
                    'message': 'Login successful.',
                    'token': token
                }
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                return Response({'status': 'error', 'message': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'status': 'error', 'message': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
        
        
class RequestResetPassword(APIView):

    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        tags=['RequestResetPassword'],
        manual_parameters=[
            openapi.Parameter('email_id', openapi.IN_FORM, type=openapi.TYPE_STRING, required=True, description="Email address where verification code will be sent."),
        ],
        responses={
            200: openapi.Response('Success', examples={"application/json": {"status": "success", "message": "Verification code sent to your email."}}),
            400: openapi.Response('Bad Request', examples={"application/json": {"status": "fail", "message": "This email is not registered."}}),
            500: openapi.Response('Internal Server Error', examples={"application/json": {"status": "error", "message": "Internal server error message"}})
        },
        security=[{'Bearer': []}]
    )
    def post(self, request):

        serializer = EmailSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            email_id = serializer.validated_data['email_id']
            try:
                user = User.objects.get(email_id=email_id)

                # Generate and store the verification code
                verification_code = get_random_string(length=6, allowed_chars='0123456789')
                hashed_code = make_password(verification_code)
                user.verify_code = hashed_code
                user.verify_code_expire_at = timezone.now() + timedelta(minutes=10)
                user.save()

                # Send verification code via email
                send_mail(
                    'Password Reset Verification Code',
                    f'Your verification code is {verification_code}',
                    'from@example.com',
                    [email_id],  # Fixed: email_id instead of email
                    fail_silently=False,
                )

                response_data = {
                    'status': 'success',
                    'message': 'Verification code sent to your email',
                }
                return Response(response_data, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                response_data = {
                    'status': 'error',
                    'message': 'This email is not registered.'
                }
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                response_data = {
                    'status': 'error',
                    'message': 'Internal server error occurred.',
                    'details': str(e)  # Optional: include the error details for debugging
                }
                return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
              
    
class VerifyCode(APIView):

    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        tags=['VerifyCode'],
        manual_parameters=[
            openapi.Parameter('code', openapi.IN_FORM, type=openapi.TYPE_STRING, required=True, description="Verification code sent to the user's email"),
            openapi.Parameter('email_id', openapi.IN_FORM, type=openapi.TYPE_STRING, required=True, description="Email address where verification code will be sent."),
        ],
        responses={
            200: openapi.Response('Success', examples={"application/json": {"status": "success", "message": "Code verified successfully", "token": "your_jwt_token_here"}}),
            400: openapi.Response('Bad Request', examples={"application/json": {"status": "error", "message": "Invalid or expired verification code."}}),
            404: openapi.Response('Not Found', examples={"application/json": {"status": "error", "message": "User with specified email does not exist"}}),
            500: openapi.Response('Internal Server Error', examples={"application/json": {"status": "error", "message": "Internal server error"}}),
        },
        security=[{'Bearer': []}]
    )
    def post(self, request):

        email_id = request.data.get('email_id')
        code = request.data.get('code')

        try:
            user = User.objects.get(email_id=email_id)

            if user.verify_code and check_password(code, user.verify_code) and user.verify_code_expire_at > timezone.now():
                user.verify_code = None  
                user.verify_code_expire_at = None 
                user.is_verify = True
                user.save()
                
  

                response_data = {
                    'status': 'success',
                    'message': 'Code verified successfully.',
                 
                }
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                response_data = {
                    'status': 'error',
                    'message': 'Invalid or expired verification code.'
                }
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            response_data = {
                'status': 'error',
                'message': 'User with specified email does not exist.'
            }
            return Response(response_data, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            response_data = {
                'status': 'error',
                'message': 'Internal server error',
                'details': str(e)
            }
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class ResetPassword(APIView):
    """
    API view to handle resetting the user's password.
    """
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        tags=['ResetPassword'],
        manual_parameters=[
            openapi.Parameter('new_password', openapi.IN_FORM, type=openapi.TYPE_STRING, required=True, description="New password for the user"),
            openapi.Parameter('email_id', openapi.IN_FORM, type=openapi.TYPE_STRING, required=True, description="Email address associated with the user."),
        ],
        responses={
            200: openapi.Response('Success', examples={"application/json": {"status": "success", "message": "Password updated successfully."}}),
            400: openapi.Response('Bad Request', examples={"application/json": {"status": "fail", "message": "Error updating password."}}),
            404: openapi.Response('Not Found', examples={"application/json": {"status": "fail", "message": "User with the specified email does not exist."}}),
            500: openapi.Response('Internal Server Error', examples={"application/json": {"status": "error", "message": "Internal server error message"}})
        },
        security=[{'Bearer': []}]
    )
    def post(self, request):
        email_id = request.data.get('email_id')
        new_password = request.data.get('new_password')

        if not email_id or not new_password:
            return Response({'status': 'fail', 'message': 'Email ID and new password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch user based on email_id
            user = User.objects.get(email_id=email_id)

            # Check if the user's verification code is None and the user is verified
            if user.verify_code is None and user.is_verify:
                # Validate the new password using a serializer
                serializer = PasswordResetSerializer(data=request.data, context={'request': request})
                if serializer.is_valid():
                    # Update and hash the new password
                    user.set_password(serializer.validated_data['new_password'])
                    user.save()

                    return Response({'status': 'success', 'message': 'Password updated successfully.'}, status=status.HTTP_200_OK)
                else:
                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            else:
                return Response({'status': 'fail', 'message': 'Cannot reset password. Verification incomplete or code is still active.'}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({'status': 'fail', 'message': 'User with specified email does not exist.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'status': 'error', 'message': 'Internal server error occurred.', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)