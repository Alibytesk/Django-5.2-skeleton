from django.shortcuts import render, redirect
from django.views.generic.base import View
from account.models import User, Otp, EmailCode, ChangeEmailCode
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import mixins
from account.form import *
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
from django.utils.crypto import get_random_string
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
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

class LogoutView(View):

    def get(self, request):
        logout(request)
        messages.success(request, 'you are logged out')
        return redirect('/')

class ChangePasswordView(mixins.LoginRequiredMixin, View):

    def get(self, request):
        if request.user.is_authenticated:
            form = ChangePasswordForm()
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('/')

    def post(self, request):
        if request.user.is_authenticated:
            form = ChangePasswordForm(data=request.POST)
            if form.is_valid():
                cleaned_data = form.cleaned_data
                if cleaned_data.get('password1') == cleaned_data.get('confirm_password'):
                    user = User.objects.get(phone=request.user.phone)
                    if user.check_password(cleaned_data.get('current_password')):
                        if not cleaned_data.get('current_password') == cleaned_data.get('password1'):
                            user.set_password(cleaned_data['password1'])
                            user.save()
                            messages.success(request, 'successfully updated password')
                            return redirect('/admin/')
                        else:
                            form.add_error('password1', 'current password and new password are same')
                    else:
                        form.add_error('current_password', 'invalid password')
                else:
                    form.add_error('password1', 'password does not Match')
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('/')

class ForgotPasswordView(View):

    def get(self, request):
        if not request.user.is_authenticated:
            form = ForgotPasswordForm()
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('/')

    def post(self, request):
        if not request.user.is_authenticated:
            form = ForgotPasswordForm(data=request.POST)
            if form.is_valid():
                cleaned_data = form.cleaned_data
                if User.objects.filter(email__exact=cleaned_data['email']).exists():
                    user = User.objects.get(email=cleaned_data['email'])
                    subject, template_name, context = 'reset your password', 'account/reset_your_password.html', {
                        'user': user,
                        'domain': get_current_site(request),
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': default_token_generator.make_token(user)
                    }
                    message = render_to_string(template_name=template_name, context=context)
                    EmailMessage(subject, message, to=[cleaned_data.get('email')]).send()
                    messages.success(request, 'Password reset email has been sent to your email address')
                    return redirect('account:login')
                else:
                    form.add_error('email', 'email is not exists')
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('/')

class ResetPasswordView(View):

    def get(self, request, uidb64, token):
        try:
            u_id = urlsafe_base64_decode(uidb64).decode()
            user = User._default_manager.get(pk=u_id)
        except(User.DoesNotExist, TypeError, ValueError, OverflowError):
            user = None
        if user is not None and default_token_generator.check_token(user, token):
            request.session['uid'] = u_id
            messages.success(request, 'reset your password')
            return redirect('account:setpassword')
        else:
            messages.error(request, 'this link has been expired')
            return redirect('account:login')

class SetPasswordView(View):

    def get(self, request):
        if request.session['uid'] and not request.user.is_authenticated:
            context = {
                'form': SetPasswordForm(request.user)
            }
            return render(request, 'account/authenticate.html', context)
        else:
            return redirect('/')

    def post(self, request):
        if request.session['uid'] and not request.user.is_authenticated:
            form = SetPasswordForm(request.user, data=request.POST)
            if form.is_valid():
                cleaned_data = form.cleaned_data
                if User.objects.filter(pk=request.session['uid']).exists():
                    user = User.objects.get(pk=request.session['uid'])
                    if not user.check_password(cleaned_data['new_password1']):
                        if cleaned_data.get('new_password1') == cleaned_data.get('new_password2'):
                            user.set_password(cleaned_data.get('new_password1'))
                            user.save()
                            messages.success(request, 'password reset successfully')
                            return redirect('account:login')
                        else:
                            form.add_error('new_password1', 'password does not Match')
                    else:
                        form.add_error('new_password1', 'password is same last password')
                else:
                    return redirect('/')
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('/')

class UserUpdateView(View):

    def get(self, request):
        if request.user.is_authenticated:
            form = UserUpdateForm(instance=request.user, request=request)
            return render(request, 'account/profile.html', context={'form':form})
        else:
            return redirect('/')

    def post(self, request):
        if request.user.is_authenticated:
            form = UserUpdateForm(instance=request.user, data=request.POST, request=request)
            if form.is_valid():
                form.save(commit=True)
                return redirect('account:dashboard')
            return render(request, 'account/profile.html', context={'form':form})
        else:
            return redirect('/')

class EmailCodeGenerator(mixins.LoginRequiredMixin, View):

    def get(self, request):
        if not request.user.is_email_verify and request.user.is_authenticated:
            if EmailCode.objects.filter(user=request.user).exists():
                EmailCode.objects.get(user=request.user).delete()
            code = randint(121212, 989898)
            subject, context = 'email verify', dict({
                'user':request.user,
                'code': code
            })
            EmailMessage(
                subject,
                render_to_string(template_name='account/email_verify.html', context=context),
                to=[request.user.email]
            ).send()
            EmailCode.objects.create(code=code, user=request.user)
            messages.success(request, 'email verification has been sent to your email address')
            return redirect('account:email_verify')
        else:
            return redirect('account:dashboard')

class EmailVerifyView(mixins.LoginRequiredMixin, View):

    def get(self, request):
        if not request.user.is_email_verify and request.user.is_authenticated:
            form = EmailVerifyForm(instance=request.user)
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('account:dashboard')

    def post(self, request):
        if not request.user.is_email_verify and request.user.is_authenticated:
            form = EmailVerifyForm(instance=request.user, data=request.POST)
            if form.is_valid():
                cleaned_data = form.cleaned_data
                if EmailCode.objects.filter(code=cleaned_data['code'], user=request.user).exists():
                    request.user.is_email_verify = True
                    request.user.save()
                    EmailCode.objects.get(code=cleaned_data['code'], user=request.user).delete()
                    return redirect('account:dashboard')
                else:
                    form.add_error('code', 'invalid code')
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('account:dashboard')

class ChangeEmailCodeGenerator(mixins.LoginRequiredMixin, View):

    def get(self, request):
        if request.user.is_email_verify and request.user.is_authenticated:
            if ChangeEmailCode.objects.filter(user=request.user):
                ChangeEmailCode.objects.get(user=request.user).delete()
            code = randint(111111, 999999)
            subject, context = 'change email', dict({
                'user':request.user,
                'code':code,
            })
            EmailMessage(
                subject,
                render_to_string('account/change_email.html', context=context),
                to=[request.user.email]
            ).send()
            ChangeEmailCode.objects.create(user=request.user, code=code).save()
            messages.success(request, 'email verification has been sent to your email address')
            return redirect('account:change_email')
        else:
            return redirect('account:dashboard')


class ChangeEmailView(mixins.LoginRequiredMixin, View):

    def get(self, request):
        if ChangeEmailCode.objects.filter(user=request.user).exists() and request.user.is_email_verify:
            form = ChangeEmailForm(instance=request.user)
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('account:dashboard')

    def post(self, request):
        if ChangeEmailCode.objects.filter(user=request.user).exists() and request.user.is_email_verify:
            form = ChangeEmailForm(instance=request.user, data=request.POST)
            if form.is_valid():
                cleaned_data = form.cleaned_data
                if ChangeEmailCode.objects.filter(user=request.user, code=cleaned_data['code']).exists():
                    ch = ChangeEmailCode.objects.get(user=request.user, code=cleaned_data['code'])
                    ch.step2 = True
                    ch.save()
                    return redirect('account:set_email')
                else:
                    form.add_error('code', 'invalid code')
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('account:dashboard')

class SetEmailView(mixins.LoginRequiredMixin, View):

    def get(self, request):
        if ChangeEmailCode.objects.filter(user=request.user, step2=True).exists():
            form = SetNewEmailForm()
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('account:dashboard')

    def post(self, request):
        if ChangeEmailCode.objects.filter(user=request.user).exists():
            ch = ChangeEmailCode.objects.get(user=request.user)
            if ch.step2:
                form = SetNewEmailForm(data=request.POST)
                if form.is_valid():
                    cleaned_data = form.cleaned_data
                    if not User.objects.filter(email=cleaned_data['email']).exists():
                        request.user.email = cleaned_data['email']
                        request.user.is_email_verify = False
                        request.user.save()
                        ChangeEmailCode.objects.get(user=request.user, step2=True).delete()
                        return redirect('account:dashboard')
                    else:
                        form.add_error('email', 'this email is already exists')
            return render(request, 'account/authenticate.html', context={'form':form})
        else:
            return redirect('account:dashboard')