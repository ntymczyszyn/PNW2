from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
import json
from django.views.decorators.http import require_POST
from django.core.paginator import Paginator
from .models import Alert, ModelVersions

# import manager functions for model management
from model_management.manager import get_active_model_path, set_active_model, request_retraining
from model_management.training_data import get_training_stats
from model_management.trainer import TrainingError, train_one_class_svm


def staff_required(view_func):
    return user_passes_test(lambda user: user.is_staff)(view_func)


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


@login_required
@require_POST
def alert_bulk_update_status(request):
    """Aktualizuje status wielu alertów na raz."""
    try:
        data = json.loads(request.body)
        alert_ids = data.get('alert_ids', [])
        new_status = data.get('status')
        
        if not alert_ids or new_status is None:
            return JsonResponse({'success': False, 'error': 'Brak danych'}, status=400)
            
        new_status = int(new_status)
        if new_status in [0, 1, 2]:
            updated = Alert.objects.filter(id__in=alert_ids).update(feedback_status=new_status)
            return JsonResponse({
                'success': True,
                'updated_count': updated
            })
            
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
        
    return JsonResponse({'success': False, 'error': 'Błąd formatowania'}, status=400)


@login_required
@staff_required
def model_versions(request):
    """List available model versions with metrics and actions."""
    versions = ModelVersions.objects.all()
    context = {
        'versions': versions,
    }
    return render(request, 'model_versions.html', context)


@login_required
@staff_required
def model_training(request):
    """Show training data summary and start-training controls."""
    active_model = ModelVersions.objects.filter(is_active=True).order_by('-created_at').first()
    context = {
        'stats': get_training_stats(),
        'active_model': active_model,
    }
    return render(request, 'model_training.html', context)


@login_required
@staff_required
@require_POST
def start_training_view(request):
    try:
        model_id = request.POST.get('model_id')
        model_id = int(model_id) if model_id else None
    except (TypeError, ValueError):
        model_id = None

    parent_version_tag = None
    if model_id:
        base_model = ModelVersions.objects.filter(pk=model_id).first()
        if base_model:
            parent_version_tag = base_model.version_tag

    try:
        result = train_one_class_svm(parent_version_tag=parent_version_tag)
        return JsonResponse({'ok': True, 'info': result})
    except TrainingError as exc:
        return JsonResponse({'ok': False, 'error': str(exc)}, status=400)
    except FileNotFoundError as exc:
        return JsonResponse({'ok': False, 'error': str(exc)}, status=400)
    except Exception as exc:
        return JsonResponse({'ok': False, 'error': str(exc)}, status=500)


@login_required
@staff_required
@require_POST
def set_active_model_view(request):
    try:
        model_id = int(request.POST.get('model_id'))
    except (TypeError, ValueError):
        return JsonResponse({'success': False, 'error': 'Invalid model_id'}, status=400)

    ok = set_active_model(model_id)
    return JsonResponse({'success': ok})


@login_required
@staff_required
@require_POST
def request_retrain_view(request):
    try:
        model_id = request.POST.get('model_id')
        model_id = int(model_id) if model_id else None
    except (TypeError, ValueError):
        model_id = None

    resp = request_retraining(model_id=model_id)
    return JsonResponse(resp)

