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

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'network_monitor.settings')
django.setup()

from network_monitor.models import Alert
from model_management.manager import get_active_model_path


logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
# Default fallback model path (kept for backward compatibility)
MODEL_PATH = BASE_DIR / 'checkpoints' / 'one_class_svm_model_mix.pkl'

# Mapowanie cech z CICFlowMeter na używane w modelu
# FEATURE_MAP = {
#     'bwd_pkt_len_std':   ' Bwd Packet Length Std',
#     'bwd_pkt_len_max':   'Bwd Packet Length Max',
#     'bwd_pkt_len_mean':  ' Bwd Packet Length Mean',
#     'bwd_seg_size_avg':  ' Avg Bwd Segment Size',
#     'pkt_len_std':       ' Packet Length Std',
#     'pkt_len_max':       ' Max Packet Length',
#     'pkt_len_var':       ' Packet Length Variance',
#     'pkt_size_avg':      ' Average Packet Size',
#     'pkt_len_mean':      ' Packet Length Mean',
#     'fwd_iat_std':       ' Fwd IAT Std',
#     'idle_max':         ' Idle Max',
#     'flow_iat_max':     ' Flow IAT Max',
#     'idle_mean':        'Idle Mean',
#     'fwd_iat_max':      ' Fwd IAT Max',
#     'idle_min':         ' Idle Min',
#     'flow_iat_std':     ' Flow IAT Std'
# }

FEATURE_MAP = {
    "dst_port": " Destination Port",
    "flow_duration": " Flow Duration",
    "tot_fwd_pkts": " Total Fwd Packets",
    "tot_bwd_pkts": " Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": " Total Length of Bwd Packets",
    "fwd_pkt_len_max": " Fwd Packet Length Max",
    "fwd_pkt_len_min": " Fwd Packet Length Min",
    "fwd_pkt_len_mean": " Fwd Packet Length Mean",
    "fwd_pkt_len_std": " Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": " Bwd Packet Length Min",
    "bwd_pkt_len_mean": " Bwd Packet Length Mean",
    "bwd_pkt_len_std": " Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": " Flow Packets/s",
    "flow_iat_mean": " Flow IAT Mean",
    "flow_iat_std": " Flow IAT Std",
    "flow_iat_max": " Flow IAT Max",
    "flow_iat_min": " Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": " Fwd IAT Mean",
    "fwd_iat_std": " Fwd IAT Std",
    "fwd_iat_max": " Fwd IAT Max",
    "fwd_iat_min": " Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": " Bwd IAT Mean",
    "bwd_iat_std": " Bwd IAT Std",
    "bwd_iat_max": " Bwd IAT Max",
    "bwd_iat_min": " Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "fwd_urg_flags": " Fwd URG Flags",
    "fwd_header_len": " Fwd Header Length",
    "bwd_header_len": " Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": " Bwd Packets/s",
    "pkt_len_min": " Min Packet Length",
    "pkt_len_max": " Max Packet Length",
    "pkt_len_mean": " Packet Length Mean",
    "pkt_len_std": " Packet Length Std",
    "pkt_len_var": " Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": " SYN Flag Count",
    "rst_flag_cnt": " RST Flag Count",
    "psh_flag_cnt": " PSH Flag Count",
    "ack_flag_cnt": " ACK Flag Count",
    "urg_flag_cnt": " URG Flag Count",
    "cwr_flag_count": " CWE Flag Count",
    "ece_flag_cnt": " ECE Flag Count",
    "down_up_ratio": " Down/Up Ratio",
    "pkt_size_avg": " Average Packet Size",
    "fwd_seg_size_avg": " Avg Fwd Segment Size",
    "bwd_seg_size_avg": " Avg Bwd Segment Size",
    "fwd_header_len.1": " Fwd Header Length.1",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": " Subflow Fwd Bytes",
    "subflow_bwd_pkts": " Subflow Bwd Packets",
    "subflow_bwd_byts": " Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": " Init_Win_bytes_backward",
    "fwd_act_data_pkts": " act_data_pkt_fwd",
    "fwd_seg_size_min": " min_seg_size_forward",
    "active_mean": "Active Mean",
    "active_std": " Active Std",
    "active_max": " Active Max",
    "active_min": " Active Min",
     "idle_mean": "Idle Mean",
    "idle_std": " Idle Std",
    "idle_max": " Idle Max",
    "idle_min": " Idle Min"
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
        
        # wymagane cechy
        required_features = list(FEATURE_MAP.keys())
        missing_features = [feat for feat in required_features if feat not in df.columns]
        if len(missing_features) == 1 and missing_features[0] == 'fwd_header_len.1':
            df['fwd_header_len.1'] = df['fwd_header_len']
        elif missing_features:
            logger.error(f"Missing required features: {missing_features}")
            return None
        X = df[required_features]
        X = X.rename(columns=FEATURE_MAP)
        
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(0)
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
