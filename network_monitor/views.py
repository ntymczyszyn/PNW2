from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.core.paginator import Paginator
from .models import Alert


@login_required
def dashboard(request):
    """Dashboard view showing currently logged in user information and alerts."""
    alerts_list = Alert.objects.all()
    
    # Paginacja - 10 alertów na stronę
    paginator = Paginator(alerts_list, 10)
    page_number = request.GET.get('page', 1)
    alerts = paginator.get_page(page_number)
    
    # Statystyki alertów
    total_alerts = Alert.objects.count()
    pending_alerts = Alert.objects.filter(feedback_status=Alert.FeedbackStatus.PENDING).count()
    confirmed_alerts = Alert.objects.filter(feedback_status=Alert.FeedbackStatus.CONFIRMED).count()
    false_alerts = Alert.objects.filter(feedback_status=Alert.FeedbackStatus.FALSE_POSITIVE).count()
    
    context = {
        'alerts': alerts,
        'total_alerts': total_alerts,
        'pending_alerts': pending_alerts,
        'confirmed_alerts': confirmed_alerts,
        'false_alerts': false_alerts,
    }
    return render(request, 'dashboard.html', context)


@login_required
def profile(request):
    """Strona profilu użytkownika."""
    return render(request, 'profile.html')


@login_required
def alert_detail(request, alert_id):
    """Zwraca szczegóły alertu jako JSON dla popup."""
    alert = get_object_or_404(Alert, id=alert_id)
    return JsonResponse({
        'id': alert.id,
        'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'source_ip': alert.source_ip,
        'destination_ip': alert.destination_ip,
        'anomaly_score': alert.anomaly_score,
        'feedback_status': alert.feedback_status,
        'feedback_status_display': alert.get_feedback_status_display(),
        'protocol': alert.protocol or 'N/A',
        'source_port': alert.source_port or 'N/A',
        'destination_port': alert.destination_port or 'N/A',
        'packet_size': alert.packet_size or 'N/A',
        'description': alert.description or 'Brak opisu',
    })


@login_required
@require_POST
def alert_update_status(request, alert_id):
    """Aktualizuje status alertu."""
    alert = get_object_or_404(Alert, id=alert_id)
    
    new_status = request.POST.get('status')
    if new_status is not None:
        try:
            new_status = int(new_status)
            if new_status in [0, 1, 2]:
                alert.feedback_status = new_status
                alert.save()
                return JsonResponse({
                    'success': True,
                    'new_status': alert.feedback_status,
                    'new_status_display': alert.get_feedback_status_display(),
                })
        except ValueError:
            pass
    
    return JsonResponse({'success': False, 'error': 'Nieprawidłowy status'}, status=400)
