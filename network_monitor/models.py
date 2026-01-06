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
