from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from account.models import User
import re

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