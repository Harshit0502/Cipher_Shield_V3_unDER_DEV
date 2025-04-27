from django.urls import path
from .views import UserSignupView, UserLoginView, PrivateKeyRetrieveView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('signup/', UserSignupView.as_view(), name='signup'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('private_key/', PrivateKeyRetrieveView.as_view(), name='private-key'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
