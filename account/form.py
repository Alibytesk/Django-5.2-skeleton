from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from account.models import User
from django.core.validators import MaxLengthValidator, EmailValidator
from account.validation import *
import re

class OtpCheckForm(forms.Form):
    code = forms.CharField(
        validators=(MaxLengthValidator(4),),
        widget=forms.TextInput(attrs={'placeholder':'code', 'class':'form-control'})
    )
    username = forms.CharField(
        validators=(MaxLengthValidator(16),),
        widget=forms.TextInput(attrs={'placeholder':'username', 'class':'form-control'})
    )
    email = forms.CharField(
        validators=(EmailValidator,),
        widget=forms.EmailInput(attrs={'placeholder':'Email Address', 'class':'form-control'})
    )
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder':'password', 'class':'form-control'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder':'confirm-password', 'class':'form-control'}))

    def clean_password(self):
        PasswordValidation.password_validation(self.cleaned_data.get('password'))


    def clean(self):
        cleaned_data = self.cleaned_data
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if confirm_password != password and confirm_password and password:
            self.add_error('password', 'password does not Match')
        else:
            return password


class UserCreationForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'password'})
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'confirm-password'})
    )

    class Meta:
        model = User
        fields = ('phone',)

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password')
        password2 = cleaned_data.get('confirm_password')
        if password2 != password1 and password2 and password1:
            raise ValueError('passwords does not Match')
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=True)
        user.set_password(self.cleaned_data.get('password'))

class UserChangeForm(forms.ModelForm):
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = User
        fields = ('phone', 'email', 'username', 'password', 'fname', 'lname', 'is_active', 'is_admin')

class LoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'placeholder':'username, phone or email', 'class':'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder':'password', 'class':'form-control'}))

    def clean_username(self):
        username: str = self.cleaned_data.get('username')
        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if re.match(email_pattern, username):
            return username
        elif username.isdigit():
            if not username.startswith('09'):
                raise forms.ValidationError('phone should start with 09 number')
            if not len(username) == 11:
                raise forms.ValidationError('phone should be 11 character')
            return username
        elif username.islower():
            if not len(username) > 4 and 16 < len(username):
                raise forms.ValidationError('username must contain at least 4 character')
            return username
        raise forms.ValidationError('invalid username')

class RegisterForm(forms.Form):
    phone = forms.CharField(
        validators=(MaxLengthValidator(11), PhoneValidator.is_phone_start_with_09,),
        widget=forms.NumberInput(attrs={
            'placeholder':'Phone number',
            'class':'form-control',
        })
    )
