from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from account.models import *
from account.form import *
from django.contrib.auth.admin import Group
admin.site.unregister(Group)
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    add_form, change_form = UserCreationForm, UserChangeForm
    list_display = ('phone', 'email', 'username')
    list_filter = ('is_admin',)
    fieldsets = (
        ('Authentication', {'fields': ('phone', 'username', 'email', 'password')}),
        ('Personal Info', {'fields': ('fname', 'lname', 'image')}),
        ('permission', {'fields': ('is_active', 'is_admin', 'is_superuser')})
    )
    add_fieldsets = (
        None, {
            'class': ('wide',),
            'fields': ('phone', 'password1', 'password2')
        }
    )
    search_fields = ordering = ('phone',)
    filter_horizontal = []