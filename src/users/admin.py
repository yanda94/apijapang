from __future__ import unicode_literals
from django.contrib import admin

from users.models import User

# Register your models here.
class UserAdmin (admin.ModelAdmin):
    list_display = ['id', 'first_name', 'last_name', 'is_active', 'name', 'phone', 'profile_picture', 'email', 'password', 'is_staff', 'is_superuser', 'last_login', 'username']
    search_fields = ['id', 'first_name', 'last_name', 'name', 'phone', 'email', 'password']

admin.site.register(User, UserAdmin)
