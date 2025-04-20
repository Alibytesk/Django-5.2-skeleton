from django.shortcuts import render, redirect
from django.views.generic.base import View
from account.models import User, Otp
from django.contrib.auth import authenticate, login
from account.form import *
from django.contrib import messages
from django.utils.crypto import get_random_string
from django.urls import reverse
from random import randint

class OtpCheckView(View):

    def get(self, request):
        Otp.clean_otp()
        if Otp.objects.filter(token=request.GET.get('token')).exists() and not request.user.is_authenticated:
            form = OtpCheckForm()
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('/')

    def post(self, request):
        Otp.clean_otp()
        form, token = OtpCheckForm(data=request.POST), request.GET.get('token')
        if Otp.objects.filter(token=token).exists() and not request.user.is_authenticated:
            if form.is_valid():
                cleaned_data = form.cleaned_data
                if User.objects.filter(email=cleaned_data['email']).exists() or User.objects.filter(username=cleaned_data['username']).exists():
                    if User.objects.filter(email=cleaned_data['email']).exists():
                        form.add_error('email', 'this email is already exists')
                    if User.objects.filter(username=cleaned_data['username']).exists():
                        form.add_error('username', 'this username is already exists')
                else:
                    if Otp.objects.filter(token=token, code=cleaned_data['code']).exists():
                        otp = Otp.objects.get(token=token, code=cleaned_data['code'])
                        User.objects.create_user(
                            phone = otp.phone,
                            username = cleaned_data.get('username'),
                            email = cleaned_data.get('email'),
                            password = cleaned_data.get('confirm_password')
                        )
                        otp.delete()
                        return redirect('account:login')
                    else:
                        form.add_error('code', 'invalid code')
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('/')

class RegisterView(View):

    def get(self, request):
        if not request.user.is_authenticated:
            form = RegisterForm()
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('/')

    def post(self, request):
        if not request.user.is_authenticated:
            form = RegisterForm(data=request.POST)
            if form.is_valid():
                phone = form.cleaned_data.get('phone')
                if not User.objects.filter(phone=phone).exists():
                    if Otp.objects.filter(phone=phone).exists():
                        Otp.objects.get(phone=phone).delete()
                    token, code = get_random_string(length=255), randint(1221, 9889)
                    Otp.objects.create(code=code, token=token, phone=phone)
                    return redirect(reverse('account:profile') + f"?token={token}")
                else:
                    form.add_error('phone', 'this phone is already exists')
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('/')

class LoginView(View):

    def get(self, request):
        if not request.user.is_authenticated:
            form = LoginForm()
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('/')

    def post(self, request):
        if not request.user.is_authenticated:
            form = LoginForm(data=request.POST)
            if form.is_valid():
                cleaned_data = form.cleaned_data
                user = authenticate(
                    username=cleaned_data.get('username'),
                    password=cleaned_data.get('password'),
                )
                if user is not None:
                    login(request, user)
                    messages.success(request, 'successfully logging')
                    return redirect('/admin/')
                else:
                    form.add_error('username', 'invalid username or password')
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('/')