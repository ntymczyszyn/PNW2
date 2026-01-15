import json
from django.http import JsonResponse, StreamingHttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import requests
from .generator import traffic_generator

# URL do analytic_pipeline API (do konfiguracji)
ANALYTICS_API_URL = "http://localhost:8000/analytics/process/"

def notify_analytics(pcap_info):
    """
    Wysyła informacje o nowym pliku pcap do analytic_pipeline przez API.
    Na razie tylko loguje - do pełnej implementacji po stronie analytics.
    """
    if not pcap_info:
        return
    
    print(f"[PCAP] Wysyłam do analyics: {pcap_info.get('filename')} ({pcap_info.get('packet_count')} packets)")
    
    # TODO: Odkomentuj gdy analytic_pipeline będzie miał endpoint API
    try:
        response = requests.post(ANALYTICS_API_URL, json=pcap_info, timeout=5)
        print(f"[PCAP] Analytics retsponse: {response.status_code}")
    except Exception as e:
        print(f"[PCAP] Error sending to analytics: {e}")


def generator(request):
    """Strona główna generatora ruchu."""
    return render(request, 'generator.html')


@require_http_methods(["GET"])
def stream_packets(request):
    """
    Stream pakietów używając Server-Sent Events.
    Automatycznie zapisuje do pcap i przesyła do analytic_pipeline.
    """
    def event_stream():
        for features, saved_file in traffic_generator.generate_normal_traffic(count=None, interval=0.5):
            response_data = features.copy()
            if saved_file:
                response_data['pcap_saved'] = saved_file
                notify_analytics(saved_file)
            data = json.dumps(response_data)
            yield f"data: {data}\n\n"
    
    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    return response


@csrf_exempt
@require_http_methods(["POST"])
def start_generator(request):
    """Uruchamia generator."""
    traffic_generator.is_running = True
    return JsonResponse({
        'status': 'started',
        'message': 'Generator uruchomiony.'
    })


@csrf_exempt
@require_http_methods(["POST"])
def stop_generator(request):
    """Zatrzymuje generator i zapisuje pozostałe pakiety."""
    saved_file = traffic_generator.stop()
    
    if saved_file:
        notify_analytics(saved_file)
    
    return JsonResponse({
        'status': 'stopped',
        'message': 'Generator zatrzymany.',
        'final_pcap': saved_file
    })


@require_http_methods(["GET"])
def generate_attack(request):
    """Generuje symulację ataku."""
    count = int(request.GET.get('count', 10))
    attack_type = request.GET.get('type', 'syn_flood')
    packets = []
    saved_files = []
    
    if attack_type == 'dos':
        generator_func = traffic_generator.generate_dos_attack(count=count, interval=0.01)
    else:
        generator_func = traffic_generator.generate_attack_traffic(count=count, interval=0.1)
    
    for features, saved_file in generator_func:
        packets.append(features)
        if saved_file:
            saved_files.append(saved_file)
            notify_analytics(saved_file)
    
    return JsonResponse({
        'status': 'success',
        'attack_type': attack_type,
        'packets_generated': len(packets),
        'packets': packets,
        'pcap_files_saved': len(saved_files)
    })


@require_http_methods(["GET"])
def analytics_status(request):
    """Zwraca status wysyłania do analytics (placeholder)."""
    return JsonResponse({
        'status': 'ok',
        'message': 'Analytics integration via API - check analytics app for status'
    })
