from django.contrib import admin
from .models import Alert


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['id', 'timestamp', 'source_ip', 'destination_ip', 'anomaly_score', 'feedback_status']
    list_filter = ['feedback_status', 'timestamp']
    search_fields = ['source_ip', 'destination_ip']
    ordering = ['-timestamp']
    readonly_fields = ['timestamp']
