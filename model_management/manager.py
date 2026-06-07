import logging
from typing import Optional

from network_monitor.models import ModelVersions

logger = logging.getLogger(__name__)


def get_active_model_path() -> Optional[str]:
    """Return file system path for the currently active model, or None."""
    try:
        active = ModelVersions.objects.filter(is_active=True).order_by('-created_at').first()
        if active:
            logger.debug(f"Active model: %s (path=%s)", active.version_tag, active.file_path)
            return active.file_path
    except Exception as e:
        logger.exception("Failed to get active model path: %s", e)
    return None


def set_active_model(model_id: int) -> bool:
    """Mark the ModelVersions instance with given id as active.

    Returns True on success, False otherwise.
    """
    try:
        mv = ModelVersions.objects.get(pk=model_id)
        mv.is_active = True
        mv.save()
        logger.info("Set active model to %s", mv.version_tag)
        from analytic_pipline.traffic_predictor import clear_model_cache
        clear_model_cache()
        return True
    except ModelVersions.DoesNotExist:
        logger.warning("ModelVersions id=%s does not exist", model_id)
        return False
    except Exception:
        logger.exception("Error setting active model id=%s", model_id)
        return False


def request_retraining(model_id: Optional[int] = None, **kwargs) -> dict:
    """Stub to request a retraining job — delegates to retraining.start_retraining.

    Returns a dict describing the request status.
    """
    from . import retraining

    try:
        task_info = retraining.start_retraining(model_id=model_id, **kwargs)
        if task_info.get('status') == 'failed':
            return {'ok': False, 'error': task_info.get('error', 'Training failed'), 'info': task_info}
        return {'ok': True, 'info': task_info}
    except Exception as e:
        logger.exception("Failed to request retraining: %s", e)
        return {'ok': False, 'error': str(e)}
