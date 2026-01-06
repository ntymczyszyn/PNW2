#!/usr/bin/env python3
"""
Skrypt konfiguracyjny dla projektu Network Monitor.
Automatycznie wykonuje migracje, tworzy superusera i dodaje przykładowe dane.

"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'network_monitor.settings')
django.setup()

from django.contrib.auth.models import User
from network_monitor.models import Alert


def run_migrations():
    print(" Wykonywanie migracji bazy danych...")
    from django.core.management import call_command
    call_command('makemigrations', verbosity=1)
    call_command('migrate', verbosity=1)
    print(" Migracje zakończone\n")


def create_superuser():
    print("Tworzenie superusera...")
    
    username = 'admin'
    email = 'admin@example.com'
    password = 'admin123'
    
    if User.objects.filter(username=username).exists():
        print(f"Użytkownik '{username}' już istnieje, pomijam...")
    else:
        User.objects.create_superuser(
            username=username,
            email=email,
            password=password
        )
        print(f" Superuser utworzony:")
        print(f"   Username: {username}")
        print(f"   Password: {password}")
        print(f"   Email: {email}")
    print()


def create_sample_alerts():
    print(" Tworzenie przykładowych alertów...")
    
    sample_alerts = [
        {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.50',
            'protocol': 'TCP',
            'source_port': 54321,
            'destination_port': 22,
            'packet_size': 1024,
            'anomaly_score': 0.95,
            'feedback_status': 0,  # Pending
            'description': 'Suspicious SSH connection attempt detected'
        },
        {
            'source_ip': '172.16.0.25',
            'destination_ip': '8.8.8.8',
            'protocol': 'UDP',
            'source_port': 53211,
            'destination_port': 53,
            'packet_size': 512,
            'anomaly_score': 0.45,
            'feedback_status': 2,  # False positive
            'description': 'Normal DNS query, marked as false positive'
        },
        {
            'source_ip': '10.10.10.150',
            'destination_ip': '192.168.1.1',
            'protocol': 'TCP',
            'source_port': 49152,
            'destination_port': 80,
            'packet_size': 2048,
            'anomaly_score': 0.88,
            'feedback_status': 1,  # Confirmed
            'description': 'Confirmed DDoS attack pattern detected'
        },
        {
            'source_ip': '203.0.113.42',
            'destination_ip': '10.0.0.100',
            'protocol': 'ICMP',
            'source_port': None,
            'destination_port': None,
            'packet_size': 64,
            'anomaly_score': 0.72,
            'feedback_status': 0,  # Pending
            'description': 'Unusual ICMP flood pattern'
        },
        {
            'source_ip': '192.168.100.200',
            'destination_ip': '172.16.50.10',
            'protocol': 'TCP',
            'source_port': 12345,
            'destination_port': 443,
            'packet_size': 1500,
            'anomaly_score': 0.62,
            'feedback_status': 0,  # Pending
            'description': 'Possible port scanning activity'
        },
    ]
    
    created_count = 0
    for alert_data in sample_alerts:
        alert, created = Alert.objects.get_or_create(
            source_ip=alert_data['source_ip'],
            destination_ip=alert_data['destination_ip'],
            defaults=alert_data
        )
        if created:
            created_count += 1
            status_display = alert.get_feedback_status_display()
            print(f"   ✓ Alert {alert.id}: {alert.source_ip} → {alert.destination_ip} "
                  f"(score: {alert.anomaly_score:.2f}, status: {status_display})")
    
    if created_count == 0:
        print(" Wszystkie przykładowe alerty już istnieją")
    else:
        print(f" Utworzono {created_count} alertów")
    print()


def print_summary():
    print("=" * 60)
    print("Konfiguracja zakończona!")
    print("=" * 60)
    print("\n Informacje o systemie:")
    print(f"   Liczba użytkowników: {User.objects.count()}")
    print(f"   Liczba alertów: {Alert.objects.count()}")
    print(f"   Alerty oczekujące: {Alert.objects.filter(feedback_status=0).count()}")
    print(f"   Alerty potwierdzone: {Alert.objects.filter(feedback_status=1).count()}")
    print(f"   Fałszywe alarmy: {Alert.objects.filter(feedback_status=2).count()}")


def main():
    print("\n" + "=" * 60)
    print("Network Monitor - skrypt inicjalizacyjny")
    print("=" * 60 + "\n")
    
    try:
        run_migrations()
        create_superuser()
        create_sample_alerts()
        print_summary()
        
    except Exception as e:
        print(f"\n Błąd podczas konfiguracji: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
