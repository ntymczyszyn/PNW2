import pickle
from pathlib import Path

import pandas as pd
import pytest
from django.test import override_settings

from analytic_pipline.features import FEATURE_MAP, flow_dicts_to_feature_matrix
from model_management.trainer import TrainingError, train_one_class_svm
from network_monitor.models import Alert, ModelVersions


def _sample_flow(**overrides):
    flow = {key: float(index + 1) for index, key in enumerate(FEATURE_MAP.keys())}
    flow.update(overrides)
    return flow


def _write_baseline_csv(path: Path, normal_rows: int = 40, attack_rows: int = 10) -> None:
    flow = _sample_flow()
    row = flow_dicts_to_feature_matrix([flow]).iloc[0].to_dict()
    rows = []
    for _ in range(normal_rows):
        rows.append({**row, "binary_label": 0})
    for _ in range(attack_rows):
        rows.append({**row, "binary_label": 1})
    pd.DataFrame(rows).to_csv(path, index=False)


@pytest.mark.django_db
def test_flow_dicts_to_feature_matrix_shape():
    matrix = flow_dicts_to_feature_matrix([_sample_flow(), _sample_flow()])
    assert matrix.shape == (2, len(FEATURE_MAP))


@pytest.mark.django_db
def test_train_one_class_svm_missing_baseline(tmp_path, settings):
    missing_path = tmp_path / "missing.csv"
    with override_settings(TRAINING_BASELINE_CSV=missing_path, BASE_DIR=tmp_path):
        with pytest.raises(FileNotFoundError):
            train_one_class_svm()


@pytest.mark.django_db
def test_train_one_class_svm_insufficient_samples(tmp_path, settings):
    baseline_path = tmp_path / "cleaned_dataset.csv"
    _write_baseline_csv(baseline_path, normal_rows=5, attack_rows=2)

    with override_settings(TRAINING_BASELINE_CSV=baseline_path, BASE_DIR=tmp_path):
        with pytest.raises(TrainingError):
            train_one_class_svm()
