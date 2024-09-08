from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

# Create your models here.

class Book(models.Model):
    book_id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=200)
    author = models.CharField(max_length=100)
    isbn = models.CharField(max_length=13, unique=True)
    pages = models.IntegerField()
   

    def __str__(self):
        return self.title

    class Meta:
        db_table = "book"
        
class UserManager(BaseUserManager):
    def create_user(self, mobile_no, firstname, lastname, email_id, password=None, **extra_fields):
        if not email_id:
            raise ValueError('The Email field must be set')
        email_id = self.normalize_email(email_id)
        user = self.model(email_id=email_id, mobile_no=mobile_no, firstname=firstname, lastname=lastname, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
        
class User(AbstractBaseUser):
    user_id = models.AutoField(primary_key=True)
    mobile_no = models.CharField(max_length=15, unique=True)
    firstname = models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    email_id = models.EmailField(max_length=100, unique=True)
    password = models.CharField(max_length=100)
    last_login = models.DateTimeField(null=True, blank=True)
    verify_code = models.CharField(max_length=128, blank=True, null=True)
    verify_code_expire_at = models.DateTimeField(blank=True, null=True)
    is_verify = models.BooleanField(default=False)

    USERNAME_FIELD = 'email_id'
    REQUIRED_FIELDS = ['mobile_no', 'firstname', 'lastname']

    objects = UserManager()

    def __str__(self):
        return f"{self.firstname} {self.lastname}"

    class Meta:
        db_table = "user"
        
    

        
