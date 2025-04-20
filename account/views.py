from django.shortcuts import render, redirect
from django.views.generic.base import View
from account.models import User
from django.contrib.auth import authenticate, login
from account.form import *
from django.contrib import messages

class LoginView(View):

    def get(self, request):
        if not request.user.is_authenticated:
            form = LoginForm()
            return render(request, 'account/login.html', context={'form':form})
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
            return render(request, 'account/login.html', context={'form':form})
        else:
            return redirect('/')