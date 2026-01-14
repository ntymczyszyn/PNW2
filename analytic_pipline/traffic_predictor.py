"""
Backend module for traffic prediction using One-Class SVM.
Processes flows from traffic_generator and saves detected attacks to database.

USAGE:
    from analytic_pipline.traffic_predictor import predict_flow
    
    result = predict_flow(flow_data)
    if result and result['is_attack']:
        print(f"ATTACK DETECTED! Saved to database.")
"""
import os
import pickle
import pandas as pd
import numpy as np
import logging
from pathlib import Path
from datetime import datetime
from .test_parser import packets_to_cic_df
# Django setup
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'network_monitor.settings')
django.setup()

from network_monitor.models import Alert

# Setup logging
logger = logging.getLogger(__name__)

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / 'analytic_pipline' / 'one_class_svm_model.pkl'

#Features required by model (based on notebook)
FEATURE_MAP = {
    'bwd_pkt_len_std':   ' Bwd Packet Length Std',
    'bwd_pkt_len_max':   'Bwd Packet Length Max',
    'bwd_pkt_len_mean':  ' Bwd Packet Length Mean',
    'bwd_seg_size_avg':  ' Avg Bwd Segment Size',
    'pkt_len_std':       ' Packet Length Std',
    'pkt_len_max':       ' Max Packet Length',
    'pkt_len_var':       ' Packet Length Variance',
    'pkt_size_avg':      ' Average Packet Size',
    'pkt_len_mean':      ' Packet Length Mean',
    'fwd_iat_std':       ' Fwd IAT Std',
    'idle_max':         ' Idle Max',
    'flow_iat_max':     ' Flow IAT Max',
    'idle_mean':        'Idle Mean',
    'fwd_iat_max':      ' Fwd IAT Max',
    'idle_min':         ' Idle Min',
    'flow_iat_std':     ' Flow IAT Std'
}

_model_cache = {'model': None, 'scaler': None, 'loaded': False}


def load_model():
    """
    Load One-Class SVM model and scaler (with caching).
    
    Returns:
        tuple: (model, scaler) or (None, None) if failed
    """
    if _model_cache['loaded']:
        return _model_cache['model'], _model_cache['scaler']
    
    try:
        if not MODEL_PATH.exists():
            logger.error(f"Model file not found: {MODEL_PATH}")
            return None, None
        
        with open(MODEL_PATH, 'rb') as f:
            model, scaler = pickle.load(f)
        
        _model_cache['model'] = model
        _model_cache['scaler'] = scaler
        _model_cache['loaded'] = True
        
        logger.info(f"Model loaded: {type(model).__name__}, Scaler: {type(scaler).__name__}")
        return model, scaler
        
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return None, None


def save_attack_to_db(flow_data, prediction, confidence):
    """
    Zapisuje wykryty atak do bazy danych Django.
    
    Args:
        flow_data (dict): Dane flow
        prediction (int): -1 (attack)
        confidence (float): Decision function score
    """
    try:
        alert, created = Alert.objects.get_or_create(
            source_ip=flow_data.get('src_ip', 'unknown'),
            destination_ip=flow_data.get('dst_ip', 'unknown'),
            anomaly_score=float(abs(confidence)),
            protocol=str(flow_data.get('protocol')),
            source_port=int(flow_data.get('src_port')) if pd.notna(flow_data.get('src_port')) else None,
            destination_port=int(flow_data.get('dst_port')) if pd.notna(flow_data.get('dst_port')) else None,
            packet_size=int(flow_data.get('pkt_len_mean', 0)),
            description=(
                f"CICFlow anomaly: "
                f"flowsize={flow_data.get('flow_bytes')} "
                f"pkts={flow_data.get('tot_fwd_pkts', 0) + flow_data.get('tot_bwd_pkts', 0)} "
                f"score={confidence:.4f}"
            ),
            feedback_status=0  # Pending
        )
        logger.info(f"✓ Attack saved to DB: ID={alert.id}")
        
    except Exception as e:
        logger.error(f"✗ Error saving attack to DB: {e}")
        import traceback
        traceback.print_exc()



def predict_packets(packets):
    """
    packets = list[scapy.Packet]
    Zwraca ALERT jeśli dowolny flow jest atakiem
    """
    try:
        model, scaler = load_model()
        if model is None:
            return None
        
        df = packets_to_cic_df(packets)

        if df is None or df.empty:
            return None
        
        # wymagane cechy
        X = df[list(FEATURE_MAP.keys())].copy()
        X.rename(columns=FEATURE_MAP, inplace=True)
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(0)
        X_scaled = scaler.transform(X)
        preds = model.predict(X_scaled)
        scores = model.decision_function(X_scaled)

        alerts = preds == -1

        if alerts.any():
            for i in np.where(alerts)[0]:
                flow = df.iloc[i].to_dict()
                save_attack_to_db(flow, preds[i], scores[i])

        return {
            "flows": len(df),
            "attacks": len(alerts),
            "is_attack": len(alerts) > 0,
            "details": alerts
        }

    except Exception as e:
        logger.error(f"CIC pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        return None


# ==============================================================================
# API funkcje (dla celów testowania/integracji)
# ==============================================================================

def get_recent_attacks(limit=10):
    """
    Pobierz ostatnie wykryte ataki z bazy.
    
    Args:
        limit (int): Maksymalna liczba wyników
        
    Returns:
        QuerySet: Lista Alert obiektów
    """
    return Alert.objects.all()[:limit]


def get_attack_statistics():
    """
    Pobierz statystyki ataków.
    
    Returns:
        dict: Statystyki
    """
    from django.db.models import Count, Avg
    from django.utils import timezone
    from datetime import timedelta
    
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    recent_alerts = Alert.objects.filter(timestamp__gte=last_24h)

    stats = {
        'total_attacks': Alert.objects.count(),
        'last_24h': recent_alerts.count(),
        'by_source_ip': recent_alerts.values('source_ip').annotate(
            count=Count('id')
        ).order_by('-count')[:10],
        'avg_confidence': recent_alerts.aggregate(
            avg=Avg('anomaly_score')
        )['avg'] or 0,
    }
    
    return stats
