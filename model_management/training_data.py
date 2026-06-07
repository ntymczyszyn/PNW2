"""Load training and validation data from baseline CSV and Alert records."""
from pathlib import Path

import pandas as pd
from django.conf import settings

from analytic_pipline.features import align_baseline_features, alerts_to_feature_matrix
from network_monitor.models import Alert


def get_baseline_path() -> Path:
    return Path(settings.TRAINING_BASELINE_CSV)


def baseline_exists() -> bool:
    return get_baseline_path().exists()


def load_baseline() -> tuple[pd.DataFrame, pd.Series]:
    """Load baseline CSV and return aligned features with binary labels."""
    path = get_baseline_path()
    if not path.exists():
        raise FileNotFoundError(
            f"Baseline dataset not found at {path}. "
            "Generate cleaned_dataset.csv from the training notebook."
        )

    df = pd.read_csv(path, low_memory=False)
    label_col = None
    for candidate in ("binary_label", "binary label"):
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        raise ValueError("Baseline CSV must contain a binary_label column.")

    drop_cols = [col for col in (" Label", "Label", label_col) if col in df.columns]
    y = df[label_col].astype(int)
    feature_df = df.drop(columns=drop_cols, errors="ignore")
    X = align_baseline_features(feature_df)
    return X, y


def load_labeled_alerts() -> dict:
    """Load False (train) and Confirmed (validation) alerts with raw_features."""
    false_alerts = Alert.objects.filter(
        feedback_status=Alert.FeedbackStatus.FALSE_POSITIVE,
        raw_features__isnull=False,
    ).exclude(raw_features=b"")
    confirmed_alerts = Alert.objects.filter(
        feedback_status=Alert.FeedbackStatus.CONFIRMED,
        raw_features__isnull=False,
    ).exclude(raw_features=b"")

    false_x, false_skipped = alerts_to_feature_matrix(false_alerts)
    confirmed_x, confirmed_skipped = alerts_to_feature_matrix(confirmed_alerts)

    return {
        "false_train_x": false_x,
        "false_skipped": false_skipped,
        "false_total": false_alerts.count(),
        "confirmed_val_x": confirmed_x,
        "confirmed_skipped": confirmed_skipped,
        "confirmed_total": confirmed_alerts.count(),
    }


def get_training_stats() -> dict:
    """Summary counts for the training UI."""
    alert_stats = load_labeled_alerts()
    return {
        "baseline_exists": baseline_exists(),
        "baseline_path": str(get_baseline_path()),
        "false_with_features": len(alert_stats["false_train_x"]),
        "false_skipped": alert_stats["false_skipped"],
        "confirmed_with_features": len(alert_stats["confirmed_val_x"]),
        "confirmed_skipped": alert_stats["confirmed_skipped"],
    }
