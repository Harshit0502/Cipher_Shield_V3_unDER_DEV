from django.urls import path
from .views import UserSignupView, UserLoginView
from .views import PrivateKeyRetrieveView
urlpatterns = [
    path('signup/', UserSignupView.as_view(), name='signup'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('auth/private_key/', PrivateKeyRetrieveView.as_view(), name='get_private_key'),
    path('private_key/<str:username>/', PrivateKeyRetrieveView.as_view(), name='private_key_retrieve'),

]
