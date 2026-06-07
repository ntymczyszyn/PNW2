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
from .test_parser import packets_to_cic_df
from .features import prepare_cicflowmeter_df

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'network_monitor.settings')
django.setup()

from network_monitor.models import Alert
from model_management.manager import get_active_model_path


logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
# Default fallback model path (kept for backward compatibility)
MODEL_PATH = BASE_DIR / 'checkpoints' / 'one_class_svm_model_mix.pkl'

_model_cache = {'model': None, 'scaler': None, 'loaded': False}


def clear_model_cache():
    """Invalidate cached model so the next load reads from disk."""
    _model_cache['model'] = None
    _model_cache['scaler'] = None
    _model_cache['loaded'] = False


def load_model():
    """
    Load One-Class SVM model and scaler (with caching).
    
    Returns:
        tuple: (model, scaler) or (None, None) if failed
    """
    if _model_cache['loaded']:
        return _model_cache['model'], _model_cache['scaler']
    
    try:
        # Prefer the active model path from manager if available
        active_path = get_active_model_path()
        path_to_use = Path(active_path) if active_path else MODEL_PATH

        if not path_to_use.exists():
            logger.error(f"Model file not found: %s", path_to_use)
            return None, None

        with open(path_to_use, 'rb') as f:
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
    """
    try:
        pickled_data = pickle.dumps(flow_data)
        alert = Alert.objects.create(
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
            feedback_status=0,
            raw_features=pickled_data
        )
        logger.info(f"Attack saved to DB: ID={alert.id}")
        
    except Exception as e:
        logger.error(f"Error saving attack to DB: {e}")
        import traceback
        traceback.print_exc()



def predict_packets(pcap_path):
    """
    pcap_path = str
    Zwraca ALERT jeśli dowolny flow jest atakiem
    """
    try:
        model, scaler = load_model()
        if model is None:
            return None
        pcap_dir_path = os.getcwd()
        pcap_full_path = os.path.join(pcap_dir_path, 'pcap_files', pcap_path)
        df = packets_to_cic_df(pcap_full_path)

        if df is None or df.empty:
            return None
        
        try:
            X = prepare_cicflowmeter_df(df)
        except ValueError as exc:
            logger.error(str(exc))
            return None

        X_scaled = scaler.transform(X)
        preds = model.predict(X_scaled)
        scores = model.decision_function(X_scaled)
        alerts = scores < -60
        saved_count = 0
        if alerts.any():
            for i in np.where(alerts)[0]:
                flow = df.iloc[i].to_dict()
                save_attack_to_db(flow, preds[i], scores[i])
                saved_count += 1

        return {
            "flows": len(df),
            "attacks": saved_count,
            "is_attack": saved_count > 0,
            "attack_indices": np.where(alerts)[0].tolist(),
            "confidence_scores": scores.tolist()
        }

    except Exception as e:
        logger.error(f"CIC pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        return None



def get_recent_attacks(limit=10):
    return Alert.objects.all()[:limit]


def get_attack_statistics():
    
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
