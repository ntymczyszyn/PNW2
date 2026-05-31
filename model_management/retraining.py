import logging
from datetime import datetime
from zoneinfo import ZoneInfo
from network_monitor.models import ModelVersions

logger = logging.getLogger(__name__)

def start_retraining(model_id=None, **kwargs):
    """Placeholder retraining entrypoint.

    This function is intentionally minimal: it should be replaced by a real
    training orchestration (Celery task, subprocess runner, ... or else).
    """
    logger.info("Retraining requested for model_id=%s, kwargs=%s", model_id, kwargs)
    
    base_version_name = None
    if model_id:
        try:
            base_model = ModelVersions.objects.get(pk=model_id)
            base_version_name = base_model.version_tag
            logger.info("Retraining will be based on parent version: %s", base_version_name)
        except ModelVersions.DoesNotExist:
            logger.warning("Base model with id=%s not found", model_id)

    # TODO: integrate with training pipeline
    response = {
        'requested_at': datetime.now(ZoneInfo("Europe/Warsaw")).isoformat() + 'Z',
        'model_id': model_id,
        'parent_version': base_version_name,
        'status': 'queued (stub)',
        'note': 'This is a stub, implement actual retraining orchestration !!!'
    }
    return response
