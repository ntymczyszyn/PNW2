from django.urls import path
from . import views

app_name = 'analytic_pipline'

urlpatterns = [
    path('process/', views.process_pcap, name='process_pcap'),
]