from django.urls import path
from .views import SendMessageView, ChatHistoryView

urlpatterns = [
    path('send/', SendMessageView.as_view(), name='send_message'),
    path('history/', ChatHistoryView.as_view(), name='chat_history'),
]
