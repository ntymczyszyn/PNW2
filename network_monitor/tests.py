"""
Testy jednostkowe dla aplikacji network_monitor.
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from .models import Alert


class AlertModelTests(TestCase):
    """Testy dla modelu Alert."""
    
    def setUp(self):
        """Tworzenie testowego alertu."""
        self.alert = Alert.objects.create(
            source_ip='192.168.1.100',
            destination_ip='10.0.0.50',
            anomaly_score=0.85,
            feedback_status=Alert.FeedbackStatus.PENDING,
            protocol='TCP',
            source_port=12345,
            destination_port=80,
            packet_size=1024,
            description='Test alert'
        )
    
    def test_alert_creation(self):
        """Test tworzenia alertu."""
        self.assertEqual(self.alert.source_ip, '192.168.1.100')
        self.assertEqual(self.alert.destination_ip, '10.0.0.50')
        self.assertEqual(self.alert.anomaly_score, 0.85)
        self.assertEqual(self.alert.feedback_status, Alert.FeedbackStatus.PENDING)
    
    def test_alert_str_representation(self):
        """Test reprezentacji tekstowej alertu."""
        expected = f"Alert {self.alert.id}: 192.168.1.100 → 10.0.0.50 (score: 0.85)"
        self.assertEqual(str(self.alert), expected)
    
    def test_default_feedback_status(self):
        """Test domyślnego statusu alertu."""
        alert = Alert.objects.create(
            source_ip='1.1.1.1',
            destination_ip='2.2.2.2',
            anomaly_score=0.5
        )
        self.assertEqual(alert.feedback_status, Alert.FeedbackStatus.PENDING)
    
    def test_alert_ordering(self):
        """Test sortowania alertów (od najnowszych)."""
        alert2 = Alert.objects.create(
            source_ip='8.8.8.8',
            destination_ip='1.1.1.1',
            anomaly_score=0.9
        )
        alerts = Alert.objects.all()
        # Nowszy alert powinien być pierwszy
        self.assertEqual(alerts[0], alert2)


class DashboardViewTests(TestCase):
    """Testy dla widoku dashboard."""
    
    def setUp(self):
        """Tworzenie testowego użytkownika i alertów."""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        # Tworzenie kilku alertów
        for i in range(15):
            Alert.objects.create(
                source_ip=f'192.168.1.{i}',
                destination_ip='10.0.0.1',
                anomaly_score=0.5 + (i * 0.03),
                feedback_status=i % 3  # 0, 1, 2 rotacyjnie
            )
    
    def test_dashboard_requires_login(self):
        """Test że dashboard wymaga zalogowania."""
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_dashboard_accessible_when_logged_in(self):
        """Test dostępu do dashboard po zalogowaniu."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
    
    def test_dashboard_contains_alerts(self):
        """Test że dashboard zawiera alerty."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('dashboard'))
        self.assertIn('alerts', response.context)
        self.assertEqual(len(response.context['alerts']), 10)  # paginacja
    
    def test_dashboard_pagination(self):
        """Test paginacji na dashboard."""
        self.client.login(username='testuser', password='testpass123')
        
        # Pierwsza strona
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(len(response.context['alerts']), 10)
        
        # Druga strona
        response = self.client.get(reverse('dashboard') + '?page=2')
        self.assertEqual(len(response.context['alerts']), 5)  # 15 - 10 = 5
    
    def test_dashboard_statistics(self):
        """Test statystyk alertów na dashboard."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('dashboard'))
        
        self.assertEqual(response.context['total_alerts'], 15)
        self.assertIn('pending_alerts', response.context)
        self.assertIn('confirmed_alerts', response.context)
        self.assertIn('false_alerts', response.context)


class ProfileViewTests(TestCase):
    """Testy dla widoku profilu."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )
    
    def test_profile_requires_login(self):
        """Test że profil wymaga zalogowania."""
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 302)
    
    def test_profile_accessible_when_logged_in(self):
        """Test dostępu do profilu po zalogowaniu."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)
    
    def test_profile_shows_username(self):
        """Test że profil pokazuje nazwę użytkownika."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('profile'))
        self.assertContains(response, 'testuser')


class AlertDetailViewTests(TestCase):
    """Testy dla widoku szczegółów alertu."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.alert = Alert.objects.create(
            source_ip='192.168.1.100',
            destination_ip='10.0.0.50',
            anomaly_score=0.85,
            protocol='TCP',
            description='Test description'
        )
    
    def test_alert_detail_requires_login(self):
        """Test że szczegóły alertu wymagają zalogowania."""
        response = self.client.get(reverse('alert_detail', args=[self.alert.id]))
        self.assertEqual(response.status_code, 302)
    
    def test_alert_detail_returns_json(self):
        """Test że szczegóły alertu zwracają JSON."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('alert_detail', args=[self.alert.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_alert_detail_contains_correct_data(self):
        """Test że szczegóły alertu zawierają poprawne dane."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('alert_detail', args=[self.alert.id]))
        data = response.json()
        
        self.assertEqual(data['source_ip'], '192.168.1.100')
        self.assertEqual(data['destination_ip'], '10.0.0.50')
        self.assertEqual(data['anomaly_score'], 0.85)
        self.assertEqual(data['protocol'], 'TCP')
    
    def test_alert_detail_404_for_nonexistent(self):
        """Test 404 dla nieistniejącego alertu."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('alert_detail', args=[9999]))
        self.assertEqual(response.status_code, 404)


class AlertUpdateStatusViewTests(TestCase):
    """Testy dla widoku aktualizacji statusu alertu."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.alert = Alert.objects.create(
            source_ip='192.168.1.100',
            destination_ip='10.0.0.50',
            anomaly_score=0.85,
            feedback_status=Alert.FeedbackStatus.PENDING
        )
    
    def test_update_status_requires_login(self):
        """Test że aktualizacja statusu wymaga zalogowania."""
        response = self.client.post(
            reverse('alert_update_status', args=[self.alert.id]),
            {'status': 1}
        )
        self.assertEqual(response.status_code, 302)
    
    def test_update_status_requires_post(self):
        """Test że aktualizacja statusu wymaga POST."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('alert_update_status', args=[self.alert.id]))
        self.assertEqual(response.status_code, 405)  # Method Not Allowed
    
    def test_update_status_success(self):
        """Test poprawnej aktualizacji statusu."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post(
            reverse('alert_update_status', args=[self.alert.id]),
            {'status': 1}
        )
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['new_status'], 1)
        
        # Sprawdź w bazie
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.feedback_status, Alert.FeedbackStatus.CONFIRMED)
    
    def test_update_status_to_false_positive(self):
        """Test zmiany statusu na fałszywy alarm."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post(
            reverse('alert_update_status', args=[self.alert.id]),
            {'status': 2}
        )
        
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.feedback_status, Alert.FeedbackStatus.FALSE_POSITIVE)
    
    def test_update_status_invalid_value(self):
        """Test nieprawidłowej wartości statusu."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post(
            reverse('alert_update_status', args=[self.alert.id]),
            {'status': 5}  # nieprawidłowa wartość
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()['success'])
    
    def test_update_status_invalid_string(self):
        """Test nieprawidłowego typu statusu."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post(
            reverse('alert_update_status', args=[self.alert.id]),
            {'status': 'invalid'}
        )
        self.assertEqual(response.status_code, 400)


class LoginLogoutTests(TestCase):
    """Testy logowania i wylogowania."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
    
    def test_login_page_accessible(self):
        """Test dostępności strony logowania."""
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
    
    def test_login_success(self):
        """Test poprawnego logowania."""
        response = self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, 302)  # przekierowanie
    
    def test_login_failure(self):
        """Test nieudanego logowania."""
        response = self.client.post(reverse('login'), {
            'username': 'testuser',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 200)  # pozostaje na stronie
    
    def test_logout(self):
        """Test wylogowania."""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post(reverse('logout'))
        self.assertEqual(response.status_code, 302)
        
        # Po wylogowaniu dashboard powinien przekierować na login
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 302)
