from django.contrib import admin
from .models import Alert, ModelVersions


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['id', 'timestamp', 'source_ip', 'destination_ip', 'anomaly_score', 'feedback_status']
    list_filter = ['feedback_status', 'timestamp']
    search_fields = ['source_ip', 'destination_ip']
    ordering = ['-timestamp']
    readonly_fields = ['timestamp']


@admin.register(ModelVersions)
class ModelVersionsAdmin(admin.ModelAdmin):
    list_display = [
        'version_tag',
        'parent_version',
        'is_active',
        'precision',
        'recall',
        'f1_score',
        'created_at',
        'file_path',
    ]
    list_filter = ['is_active', 'created_at']
    search_fields = ['version_tag', 'parent_version', 'file_path']
    ordering = ['-created_at']
    readonly_fields = ['created_at']
    fieldsets = (
        (None, {
            'fields': ('version_tag', 'parent_version', 'file_path', 'is_active'),
        }),
        ('Metryki walidacyjne', {
            'fields': ('precision', 'recall', 'f1_score'),
            'description': 'Opcjonalne. Może zostać puste przy ręcznym imporcie istniejącego modelu.',
        }),
        ('Informacje', {
            'fields': ('created_at',),
        }),
    )
