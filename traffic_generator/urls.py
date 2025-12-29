"""
URL routing dla generatora ruchu.
"""
from django.urls import path
from . import views

app_name = 'traffic_generator'

urlpatterns = [
    path('api/packets/', views.realtime_packets, name='realtime_packets'),
    path('api/stream/', views.stream_packets, name='stream_packets'),
    path('api/start/', views.start_generator, name='start_generator'),
    path('api/attack/', views.generate_attack, name='generate_attack'),
]


