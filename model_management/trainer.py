"""One-Class SVM training pipeline."""
import logging
import pickle
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd
from django.conf import settings
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import QuantileTransformer
from sklearn.svm import OneClassSVM

from analytic_pipline.features import MODEL_FEATURE_COLUMNS
from model_management.training_data import get_baseline_path, load_baseline, load_labeled_alerts
from network_monitor.models import ModelVersions

logger = logging.getLogger(__name__)

RANDOM_STATE = 42
MIN_NORMAL_SAMPLES = 10
MIN_VALIDATION_SAMPLES = 1


class TrainingError(Exception):
    """Raised when training cannot proceed due to invalid input."""


def _evaluate(model, X_val: pd.DataFrame, y_val: pd.Series) -> dict:
    X_scaled = model["scaler"].transform(X_val)
    y_pred = model["estimator"].predict(X_scaled)
    y_pred_bin = np.array([1 if pred == -1 else 0 for pred in y_pred])
    y_true = y_val.to_numpy()

    return {
        "precision": float(precision_score(y_true, y_pred_bin, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred_bin, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred_bin, zero_division=0)),
        "validation_samples": int(len(y_val)),
        "attack_samples": int((y_true == 1).sum()),
        "normal_samples": int((y_true == 0).sum()),
    }


def _build_datasets() -> tuple[pd.DataFrame, pd.Series, pd.DataFrame, pd.Series, dict]:
    baseline_x, baseline_y = load_baseline()
    alert_data = load_labeled_alerts()

    baseline_train_x, baseline_val_x, baseline_train_y, baseline_val_y = train_test_split(
        baseline_x,
        baseline_y,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=baseline_y,
    )

    train_x = baseline_train_x[baseline_train_y == 0]
    if not alert_data["false_train_x"].empty:
        train_x = pd.concat([train_x, alert_data["false_train_x"]], ignore_index=True)

    val_parts_x = [baseline_val_x]
    val_parts_y = [baseline_val_y]
    if not alert_data["confirmed_val_x"].empty:
        val_parts_x.append(alert_data["confirmed_val_x"])
        val_parts_y.append(pd.Series([1] * len(alert_data["confirmed_val_x"])))

    val_x = pd.concat(val_parts_x, ignore_index=True)
    val_y = pd.concat(val_parts_y, ignore_index=True)

    meta = {
        "baseline_train_normals": int((baseline_train_y == 0).sum()),
        "baseline_validation_samples": int(len(baseline_val_y)),
        "false_train_added": int(len(alert_data["false_train_x"])),
        "false_skipped": alert_data["false_skipped"],
        "confirmed_validation_added": int(len(alert_data["confirmed_val_x"])),
        "confirmed_skipped": alert_data["confirmed_skipped"],
    }
    return train_x, baseline_train_y, val_x, val_y, meta


def train_one_class_svm(parent_version_tag: str | None = None) -> dict:
    """Train One-Class SVM, validate, persist pickle and ModelVersions row."""
    train_x, _, val_x, val_y, meta = _build_datasets()

    if len(train_x) < MIN_NORMAL_SAMPLES:
        raise TrainingError(
            f"Need at least {MIN_NORMAL_SAMPLES} normal training samples, got {len(train_x)}."
        )
    if len(val_x) < MIN_VALIDATION_SAMPLES:
        raise TrainingError("Validation set is empty.")

    train_x = train_x.reindex(columns=MODEL_FEATURE_COLUMNS).fillna(0)
    val_x = val_x.reindex(columns=MODEL_FEATURE_COLUMNS).fillna(0)

    scaler = QuantileTransformer(output_distribution="normal")
    train_scaled = scaler.fit_transform(train_x)
    estimator = OneClassSVM(
        gamma="auto",
        kernel="rbf",
        nu=0.01,
        tol=0.01,
        verbose=False,
        cache_size=500,
    )
    estimator.fit(train_scaled)

    metrics = _evaluate({"scaler": scaler, "estimator": estimator}, val_x, val_y)

    checkpoints_dir = Path(settings.BASE_DIR) / "checkpoints"
    checkpoints_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(ZoneInfo("Europe/Warsaw")).strftime("%Y%m%d_%H%M%S")
    version_tag = f"v-{timestamp}"
    checkpoint_path = checkpoints_dir / f"one_class_svm_{timestamp}.pkl"

    with open(checkpoint_path, "wb") as handle:
        pickle.dump((estimator, scaler), handle)

    model_version = ModelVersions.objects.create(
        version_tag=version_tag,
        parent_version=parent_version_tag,
        file_path=str(checkpoint_path),
        is_active=False,
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1_score=metrics["f1_score"],
    )

    logger.info(
        "Training complete: version=%s path=%s f1=%.4f",
        version_tag,
        checkpoint_path,
        metrics["f1_score"],
    )

    return {
        "status": "completed",
        "model_version_id": model_version.id,
        "version_tag": version_tag,
        "file_path": str(checkpoint_path),
        "parent_version": parent_version_tag,
        "baseline_csv": str(get_baseline_path()),
        "training_samples": int(len(train_x)),
        "metrics": metrics,
        "data_summary": meta,
    }
