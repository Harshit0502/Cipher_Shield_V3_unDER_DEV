from django.urls import path
from .views import SendMessageView, ChatHistoryView
from .views import PublicKeyRetrieveView
urlpatterns = [
    path('chat/send/', SendMessageView.as_view(), name='send_message'),
    path('chat/history/', ChatHistoryView.as_view(), name='chat_history'),
    path('auth/public_key/<str:username>/', PublicKeyRetrieveView.as_view()),
]
