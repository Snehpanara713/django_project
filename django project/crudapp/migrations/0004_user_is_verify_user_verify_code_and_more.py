# Generated by Django 5.1.1 on 2024-09-07 11:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('crudapp', '0003_user_last_login'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_verify',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='verify_code',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='verify_code_expire_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
