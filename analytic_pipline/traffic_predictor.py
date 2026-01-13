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
from sklearn.decomposition import PCA

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

# Features required by model (based on notebook)
REQUIRED_FEATURES = [
    'Bwd Packet Length Std', 
    'Bwd Packet Length Max', 
    'Bwd Packet Length Mean', 
    'Avg Bwd Segment Size', 
    'Packet Length Std', 
    'Max Packet Length', 
    'Packet Length Variance', 
    'Average Packet Size',
    'Packet Length Mean',
    'Fwd IAT Std',
    'Idle Max',
    'Flow IAT Max',
    'Idle Mean',
    'Fwd IAT Max',
    'Idle Min',
    'Flow IAT Std'
]

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


def extract_features_from_flow(flow_data):
    """
    Konwertuje flow_data z traffic_generator na features DataFrame.
    
    Args:
        flow_data (dict): Dane flow z traffic_generator
        
    Returns:
        pd.DataFrame: DataFrame z features (1 row)
    """
    # cechy musza zostać wyciagniete z głowego pakiety potrzbe cicflowmeter



    # Mapuj dane z traffic_generator na features wymagane przez model
    features = {}
    
    # Packet length statistics
    pkt_len = flow_data.get('packet_size', 0)
    features['Bwd Packet Length Std'] = flow_data.get('bwd_packet_length_std', 0)
    features['Bwd Packet Length Max'] = flow_data.get('bwd_packet_length_max', 0)
    features['Bwd Packet Length Mean'] = flow_data.get('bwd_packet_length_mean', 0)
    features['Avg Bwd Segment Size'] = flow_data.get('avg_bwd_segment_size', 0)
    features['Packet Length Std'] = flow_data.get('packet_length_std', 0)
    features['Max Packet Length'] = flow_data.get('max_packet_length', pkt_len)
    features['Packet Length Variance'] = flow_data.get('packet_length_variance', 0)
    features['Average Packet Size'] = flow_data.get('average_packet_size', pkt_len)
    features['Packet Length Mean'] = flow_data.get('packet_length_mean', pkt_len)
    
    # IAT (Inter-Arrival Time) statistics
    features['Fwd IAT Std'] = flow_data.get('fwd_iat_std', 0)
    features['Fwd IAT Max'] = flow_data.get('fwd_iat_max', 0)
    features['Flow IAT Max'] = flow_data.get('flow_iat_max', 0)
    features['Flow IAT Std'] = flow_data.get('flow_iat_std', 0)
    
    # Idle time statistics
    features['Idle Max'] = flow_data.get('idle_max', 0)
    features['Idle Mean'] = flow_data.get('idle_mean', 0)
    features['Idle Min'] = flow_data.get('idle_min', 0)
    
    return pd.DataFrame([features])


def preprocess_features(df):
    """
    Preprocessing: clean data, handle NaN/inf.
    
    Args:
        df (pd.DataFrame): Raw features
        
    Returns:
        pd.DataFrame: Cleaned features
    """
    try:
        # Strip column names
        df.columns = df.columns.str.strip()
        
        # Keep only required features
        missing_cols = [col for col in REQUIRED_FEATURES if col not in df.columns]
        if missing_cols:
            for col in missing_cols:
                df[col] = 0
        
        df = df[REQUIRED_FEATURES]
        
        # Handle infinity and NaN
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0)
        
        # Ensure numeric
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        df = df.fillna(0)
        
        return df
        
    except Exception as e:
        logger.error(f"Error preprocessing: {e}")
        return None


def apply_scale(X, scaler):
    """
        X (pd.DataFrame): Feature matrix
        scaler: Fitted scaler
        n_components (int): Number of PCA components
        
    Returns:
        np.ndarray: Transformed and scaled features
    """
    try:
        # Scale
        X_scaled = scaler.transform(X)
        
        return X_scaled
        
    except Exception as e:
        logger.error(f"Error in PCA/scaling: {e}")
        return None


def predict_flow(flow_data):
    """
    GŁÓWNA FUNKCJA - wywołaj tę funkcję z traffic_generator!
    
    Przetwarza flow, robi predykcję i zapisuje do bazy jeśli wykryje atak.
    
    Args:
        flow_data (dict): Słownik z danymi flow z traffic_generator
        
    Returns:
        dict: {'prediction': 1/-1, 'label': 'BENIGN'/'ATTACK', 
               'confidence': float, 'is_attack': bool}
        lub None jeśli błąd
    
    Example:
        >>> flow = {
        ...     'source_ip': '192.168.1.1',
        ...     'dest_ip': '10.0.0.1',
        ...     'packet_size': 1500,
        ...     'protocol': 'TCP',
        ...     ...
        ... }
        >>> result = predict_flow(flow)
        >>> if result and result['is_attack']:
        ...     print("ATTACK!")
    """
    try:
        # 1. Load model
        model, scaler = load_model()
        if model is None:
            logger.error("Model not loaded")
            return None
        
        # 2. Extract features
        df = extract_features_from_flow(flow_data)
        if df is None or df.empty:
            logger.error("Failed to extract features")
            return None
        
        # 3. Preprocess
        df_clean = preprocess_features(df)
        if df_clean is None or df_clean.empty:
            logger.error("Failed to preprocess")
            return None
        
        # 4. Apply scaling
        X_scaled = apply_scale(df_clean, scaler)
        if X_scaled is None:
            logger.error("Failed to transform features")
            return None
        
        # 5. Predict
        prediction = model.predict(X_scaled)[0]  # 1 = BENIGN, -1 = ATTACK
        decision_score = model.decision_function(X_scaled)[0]
        
        result = {
            'prediction': int(prediction),
            'label': 'BENIGN' if prediction == 1 else 'ATTACK',
            'confidence': float(abs(decision_score)),
            'is_attack': bool(prediction == -1)
        }
        
        # 6. Jeśli ATTACK - zapisz do bazy
        if result['is_attack']:
            save_attack_to_db(flow_data, prediction, decision_score)
            logger.warning(f"🚨 ATTACK DETECTED: {flow_data.get('source_ip')} → {flow_data.get('dest_ip')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in predict_flow: {e}")
        import traceback
        traceback.print_exc()
        return None


def save_attack_to_db(flow_data, prediction, confidence):
    """
    Zapisuje wykryty atak do bazy danych Django.
    
    Args:
        flow_data (dict): Dane flow
        prediction (int): -1 (attack)
        confidence (float): Decision function score
    """
    try:
        alert = Alert.objects.create(
            source_ip=flow_data.get('source_ip', 'unknown'),
            destination_ip=flow_data.get('dest_ip', 'unknown'),
            anomaly_score=abs(confidence),  # Confidence z modelu
            protocol=flow_data.get('protocol', 'TCP'),
            source_port=flow_data.get('source_port'),
            destination_port=flow_data.get('dest_port'),
            packet_size=flow_data.get('packet_size'),
            description=f"Attack detected by One-Class SVM (score: {prediction})",
            feedback_status=Alert.FeedbackStatus.PENDING
        )
        logger.info(f"✓ Attack saved to DB: ID={alert.id}")
        
    except Exception as e:
        logger.error(f"✗ Error saving attack to DB: {e}")
        import traceback
        traceback.print_exc()


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
