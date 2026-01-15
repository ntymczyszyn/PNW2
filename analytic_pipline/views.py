from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import json
from .traffic_predictor import predict_packets
from scapy.all import IP, TCP, UDP

@csrf_exempt
@require_http_methods(["POST"])
def process_pcap(request):
    """
    Odbiera informacje o PCAP od traffic_generator i uruchamia predykcję.
    """
    try:
        data = json.loads(request.body)
        pcap_file = data.get('filename')
        
        if not pcap_file:
            return JsonResponse({
                'status': 'error',
                'message': 'No pcap filename provided'
            }, status=400)
        
        # Wczytaj pakiety z pliku PCAP
        #from scapy.utils import rdpcap
        #packets = rdpcap(pcap_file)
        
        # Uruchom predykcję
        result = predict_packets(pcap_file)
        print(f"[ANALYTICS] Prediction result for {pcap_file}: {result}")
        if result:
            return JsonResponse({
                'status': 'success',
                'pcap_file': pcap_file,
                'prediction': result
            }, status=200)
        else:
            return JsonResponse({
                'status': 'no_model',
                'message': 'Model not loaded'
            }, status=503)
            
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)