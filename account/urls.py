from django.urls import path
from account import views

app_name = 'account'
urlpatterns = (
    path('login/', views.LoginView.as_view(), name='login'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('profile', views.OtpCheckView.as_view(), name='profile'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    path('forgotpassword/', views.ForgotPasswordView.as_view(), name='forgot_password'),
    path('resetpassword/<uidb64>/<str:token>', views.ResetPasswordView.as_view(), name='reset_password'),
    path('setpassword', views.SetPasswordView.as_view(), name='setpassword'),
)