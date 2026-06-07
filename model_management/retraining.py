import logging

from model_management.trainer import TrainingError, train_one_class_svm
from network_monitor.models import ModelVersions

logger = logging.getLogger(__name__)


def start_retraining(model_id=None, **kwargs):
    """Run One-Class SVM retraining and persist a new model version."""
    parent_version_tag = None
    if model_id:
        try:
            base_model = ModelVersions.objects.get(pk=model_id)
            parent_version_tag = base_model.version_tag
            logger.info("Retraining based on parent version: %s", parent_version_tag)
        except ModelVersions.DoesNotExist:
            logger.warning("Base model with id=%s not found", model_id)

    try:
        result = train_one_class_svm(parent_version_tag=parent_version_tag)
        result["model_id"] = model_id
        return result
    except TrainingError as exc:
        logger.warning("Training rejected: %s", exc)
        return {
            "status": "failed",
            "model_id": model_id,
            "parent_version": parent_version_tag,
            "error": str(exc),
        }
    except FileNotFoundError as exc:
        logger.warning("Training rejected: %s", exc)
        return {
            "status": "failed",
            "model_id": model_id,
            "parent_version": parent_version_tag,
            "error": str(exc),
        }
