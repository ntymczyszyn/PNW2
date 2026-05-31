import os
import sys
import django
from datetime import datetime
from pathlib import Path

impl_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(impl_dir))

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'network_monitor.settings')
django.setup()

from network_monitor.models import ModelVersions

def populate():
    print("Populating ModelVersions in database...")
    model_path = str(impl_dir / 'checkpoints' / 'one_class_svm_model_mix.pkl')
    
    # Create 3 versions
    versions_data = [
        {
            "version_tag": "v1.0.0-initial",
            "file_path": model_path,
            "is_active": False,
            "precision": 0.85,
            "recall": 0.88,
            "f1_score": 0.86
        },
        {
            "version_tag": "v1.1.0-improved",
            "file_path": model_path,
            "is_active": True,
            "precision": 0.92,
            "recall": 0.90,
            "f1_score": 0.91
        },
        {
            "version_tag": "v1.2.0-experimental",
            "file_path": model_path,
            "is_active": False,
            "precision": 0.95,
            "recall": 0.82,
            "f1_score": 0.88
        }
    ]

    for data in versions_data:
        mv, created = ModelVersions.objects.get_or_create(
            version_tag=data["version_tag"],
            defaults={
                "file_path": data["file_path"],
                "is_active": data["is_active"],
                "precision": data["precision"],
                "recall": data["recall"],
                "f1_score": data["f1_score"]
            }
        )
        if created:
            print(f"Created version {mv.version_tag}")
        else:
            print(f"Version {mv.version_tag} already exists, skipping")

if __name__ == "__main__":
    populate()
