from django.urls import path
from .views import SendMessageView, ChatHistoryView, PublicKeyRetrieveView,DetectThreatsAPIView

urlpatterns = [
    path('send/', SendMessageView.as_view(), name='send-message'),
    path('history/', ChatHistoryView.as_view(), name='chat-history'),
    path('public_key/<str:username>/', PublicKeyRetrieveView.as_view(), name='public-key'),
    path('detect_threats/', DetectThreatsAPIView.as_view(), name='detect-threats'),  # 🔥 New API
]
