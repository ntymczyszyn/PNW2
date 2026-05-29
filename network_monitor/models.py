from django.db import models


class Alert(models.Model):
    """Model reprezentujący alert/anomalię wykrytą w ruchu sieciowym."""
    
    class FeedbackStatus(models.IntegerChoices):
        PENDING = 0, 'Pending'
        CONFIRMED = 1, 'Confirmed'
        FALSE_POSITIVE = 2, 'False'
    
    timestamp = models.DateTimeField(
        auto_now_add=True,
        help_text='Time when the anomaly was detected'
    )
    source_ip = models.CharField(
        max_length=45,
        help_text='Source IP address'
    )
    destination_ip = models.CharField(
        max_length=45,
        help_text='Destination IP address'
    )
    anomaly_score = models.FloatField(
        help_text='Score returned by the model\'s decision function (confidence metric)'
    )
    feedback_status = models.IntegerField(
        choices=FeedbackStatus.choices,
        default=FeedbackStatus.PENDING,
        help_text='Status of verification by the administrator'
    )
    
    # Dodatkowe pola przydatne do szczegółów
    protocol = models.CharField(max_length=10, blank=True, null=True)
    source_port = models.IntegerField(blank=True, null=True)
    destination_port = models.IntegerField(blank=True, null=True)
    packet_size = models.IntegerField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Alert'
        verbose_name_plural = 'Alerts'
    
    def __str__(self):
        return f"Alert {self.id}: {self.source_ip} → {self.destination_ip} (score: {self.anomaly_score:.2f})"
    
    def get_status_display_badge(self):
        """Zwraca klasę CSS dla badge'a statusu."""
        badges = {
            0: 'bg-warning',
            1: 'bg-danger',
            2: 'bg-secondary',
        }
        return badges.get(self.feedback_status, 'bg-secondary')

class ModelVersions(models.Model):
    """Model przechowujący informacje o wersjach wytrenowanego modelu."""
    version_tag = models.CharField(
        max_length=255, 
        help_text='Czytelna nazwa wersji (np. "v1.0-base").'
    )
    file_path = models.CharField(
        max_length=512, 
        help_text='Ścieżka do pliku binarnego modelu na serwerze.'
    )
    is_active = models.BooleanField(
        default=False, 
        help_text='Flaga określająca, czy model jest obecnie używany do detekcji.'
    )
    created_at = models.DateTimeField(
        auto_now_add=True, 
        help_text='Data i godzina zakończenia procesu trenowania.'
    )
    precision = models.FloatField(
        null=True, 
        blank=True,
        help_text='Precyzja modelu wyliczona na zbiorze walidacyjnym.')
    recall = models.FloatField(
        null=True, 
        blank=True, 
        help_text='Czułość modelu wyliczona na zbiorze walidacyjnym.'
    )
    f1_score = models.FloatField(
        null=True, 
        blank=True, 
        help_text='Metryka F1 (średnia harmoniczna precyzji i czułości) wyliczona na zbiorze walidacyjnym.'
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Model Version'
        verbose_name_plural = 'Model Versions'

    def __str__(self):
        active_status = " [ACTIVE]" if self.is_active else ""
        return f"{self.version_tag}{active_status}"
