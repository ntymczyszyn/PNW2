"""Shared feature mapping and conversion for inference and training."""
import pickle

import numpy as np
import pandas as pd

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
    "idle_min": " Idle Min",
}

MODEL_FEATURE_COLUMNS = list(FEATURE_MAP.values())


def _strip_column_names(df: pd.DataFrame) -> pd.DataFrame:
    result = df.copy()
    result.columns = result.columns.str.strip()
    return result


def _canonical_to_stripped() -> dict[str, str]:
    return {canonical: canonical.strip() for canonical in MODEL_FEATURE_COLUMNS}


def prepare_cicflowmeter_df(df: pd.DataFrame) -> pd.DataFrame:
    """Convert a CICFlowMeter dataframe to model feature columns."""
    required_features = list(FEATURE_MAP.keys())
    working = df.copy()
    missing_features = [feat for feat in required_features if feat not in working.columns]
    if len(missing_features) == 1 and missing_features[0] == "fwd_header_len.1":
        working["fwd_header_len.1"] = working["fwd_header_len"]
    elif missing_features:
        raise ValueError(f"Missing required features: {missing_features}")

    features = working[required_features].rename(columns=FEATURE_MAP)
    return clean_feature_matrix(features)


def flow_dicts_to_feature_matrix(flow_dicts: list[dict]) -> pd.DataFrame:
    """Convert pickled alert flow dicts to a model-ready feature matrix."""
    rows = []
    for flow in flow_dicts:
        row = {}
        for snake_key, cic_name in FEATURE_MAP.items():
            value = flow.get(snake_key)
            if snake_key == "fwd_header_len.1" and (value is None or pd.isna(value)):
                value = flow.get("fwd_header_len")
            row[cic_name] = value
        rows.append(row)
    return clean_feature_matrix(pd.DataFrame(rows))


def clean_feature_matrix(features: pd.DataFrame) -> pd.DataFrame:
    """Replace inf/nan and enforce column order."""
    ordered = features.reindex(columns=MODEL_FEATURE_COLUMNS)
    return ordered.replace([np.inf, -np.inf], np.nan).fillna(0)


def align_baseline_features(df: pd.DataFrame) -> pd.DataFrame:
    """Align baseline CSV columns to canonical model feature names."""
    stripped = _strip_column_names(df)
    canonical_to_stripped = _canonical_to_stripped()
    selected = {}
    for canonical, stripped_name in canonical_to_stripped.items():
        if stripped_name in stripped.columns:
            selected[canonical] = stripped[stripped_name]
        else:
            selected[canonical] = 0.0
    return clean_feature_matrix(pd.DataFrame(selected))


def alerts_to_feature_matrix(alerts) -> tuple[pd.DataFrame, int]:
    """Build feature matrix from Alert queryset; returns (X, skipped_count)."""
    flow_dicts = []
    skipped = 0
    for alert in alerts:
        if not alert.raw_features:
            skipped += 1
            continue
        try:
            flow_dicts.append(pickle.loads(alert.raw_features))
        except Exception:
            skipped += 1
    if not flow_dicts:
        return pd.DataFrame(columns=MODEL_FEATURE_COLUMNS), skipped
    return flow_dicts_to_feature_matrix(flow_dicts), skipped
