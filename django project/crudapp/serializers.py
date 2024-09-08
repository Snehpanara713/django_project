from rest_framework import serializers
from .models import Book, User
from django.contrib.auth.hashers import make_password

class BookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Book
        fields = ['book_id', 'title', 'author', 'isbn', 'pages']
        
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['user_id', 'mobile_no', 'firstname', 'lastname', 'email_id', 'password']
        extra_kwargs = {
            'password': {'write_only': True},  # Hide password in the response
        }

    def create(self, validated_data):
        # Hash the password
        validated_data['password'] = make_password(validated_data['password'])
        user = User.objects.create(**validated_data)
        return user


class EmailSerializer(serializers.Serializer):
    email_id = serializers.EmailField()
    
class CodeSerializer(serializers.Serializer):
    # email = serializers.EmailField()
    code = serializers.CharField(max_length=6)

class PasswordResetSerializer(serializers.Serializer):
    # email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True)
