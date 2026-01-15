"""
URL routing dla generatora ruchu.
"""
from django.urls import include, path
from . import views

app_name = 'traffic_generator'

urlpatterns = [
    path('', views.generator, name='generator'),
    path('api/stream/', views.stream_packets, name='stream_packets'),
    path('api/start/', views.start_generator, name='start_generator'),
    path('api/stop/', views.stop_generator, name='stop_generator'),
    path('api/attack/', views.generate_attack, name='generate_attack'),
    path('api/analytics/', views.analytics_status, name='analytics_status'),
    path('analytics/', include('analytic_pipline.urls')),
]


