"""
Views dla wyświetlania pakietów w czasie rzeczywistym.
"""
import json
from django.http import JsonResponse, StreamingHttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from .generator import traffic_generator


def generator(request):
    """Strona główna generatora ruchu."""
    return render(request, 'generator.html')


# Bufor dla ostatnich pakietów (w pamięci, bez bazy danych)
packet_buffer = []
MAX_BUFFER_SIZE = 100


def add_to_buffer(packet):
    """Dodaje pakiet do bufora."""
    global packet_buffer
    packet_buffer.append(packet)
    # Ograniczenie rozmiaru bufora
    if len(packet_buffer) > MAX_BUFFER_SIZE:
        packet_buffer.pop(0)


@require_http_methods(["GET"])
def realtime_packets(request):
    """
    Endpoint do pobierania pakietów w czasie rzeczywistym.
    Używa polling - zwraca JSON z ostatnimi pakietami.
    """
    return JsonResponse({
        'packets': packet_buffer[-50:],  # Ostatnie 50 pakietów
        'total': len(packet_buffer)
    })


@require_http_methods(["GET"])
def stream_packets(request):
    """
    Stream pakietów używając Server-Sent Events.
    """
    def event_stream():
        # Generuj pakiety w czasie rzeczywistym
        for packet in traffic_generator.generate_normal_traffic(count=None, interval=0.5):
            add_to_buffer(packet)
            # Format SSE
            data = json.dumps(packet)
            yield f"data: {data}\n\n"
    
    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    return response


@require_http_methods(["POST"])
def start_generator(request):
    """Uruchamia generator w tle."""
    # W prawdziwej aplikacji użyjemy Celery lub threading
    # Na razie zwróćmy informację
    return JsonResponse({
        'status': 'started',
        'message': 'Generator uruchomiony. Użyj /stream/ do otrzymywania pakietów.'
    })


@require_http_methods(["GET"])
def generate_attack(request):
    """Generuje symulację ataku."""
    count = int(request.GET.get('count', 10))
    packets = list(traffic_generator.generate_attack_traffic(count=count, interval=0.1))
    
    # Dodaj do bufora
    for packet in packets:
        add_to_buffer(packet)
    
    return JsonResponse({
        'status': 'success',
        'packets_generated': len(packets),
        'packets': packets
    })
