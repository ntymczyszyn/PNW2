import pytest
from network_monitor.models import ModelVersions
from model_management.manager import get_active_model_path, set_active_model

@pytest.fixture
def sample_models(db):
    """Fixture creating typical ModelVersions instances."""
    m1 = ModelVersions.objects.create(
        version_tag="v1.0",
        file_path="/path/to/model1",
        is_active=False
    )
    m2 = ModelVersions.objects.create(
        version_tag="v2.0",
        file_path="/path/to/model2",
        is_active=True
    )
    return m1, m2


@pytest.mark.django_db
def test_get_active_model_path(sample_models):
    path = get_active_model_path()
    assert path == "/path/to/model2"

@pytest.mark.django_db
def test_get_active_model_path_none(db):
    path = get_active_model_path()
    assert path is None

@pytest.mark.django_db
def test_set_active_model(sample_models):
    m1, m2 = sample_models
    assert not m1.is_active
    assert set_active_model(m1.id) is True
    
    # Reload from db
    m1.refresh_from_db()
    m2.refresh_from_db()
    
    assert m1.is_active is True
    assert m2.is_active is False # Due to save override in ModelVersions

@pytest.mark.django_db
def test_set_active_model_invalid_id(db):
    assert set_active_model(9999) is False