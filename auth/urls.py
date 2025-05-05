### auth/urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from auth.views import RegisterView, LogoutView, UpdatePasswordView, MeView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("update-password/", UpdatePasswordView.as_view(), name="update_password"),
    path("me/", MeView.as_view(), name="me"),
]