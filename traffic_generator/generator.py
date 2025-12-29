"""
Generator ruchu sieciowego używający Scapy.
Generuje pakiety i wyciąga podstawowe cechy do wyświetlenia w czasie rzeczywistym.
"""
import random
import time
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP
from faker import Faker

fake = Faker()


class TrafficGenerator:
    """Generator ruchu sieciowego z Scapy."""
    
    def __init__(self):
        self.protocols = ['TCP', 'UDP', 'ICMP']
        self.common_ports = [80, 443, 22, 21, 25, 53, 8080, 3306, 5432]
    
    def generate_packet(self, protocol=None):
        """
        Generuje pakiet sieciowy używając Scapy.
        
        Args:
            protocol: Protokół do użycia (TCP, UDP, ICMP) lub None dla losowego
        
        Returns:
            dict: Słownik z cechami pakietu
        """
        if protocol is None:
            protocol = random.choice(self.protocols)
        
        source_ip = fake.ipv4()
        dest_ip = fake.ipv4()
        
        # Tworzenie pakietu Scapy
        source_port = None
        dest_port = None
        
        try:
            if protocol == 'TCP':
                source_port = random.randint(1024, 65535)
                dest_port = random.choice(self.common_ports)
                packet = IP(src=source_ip, dst=dest_ip) / TCP(sport=source_port, dport=dest_port)
                packet_size = len(bytes(packet))
            elif protocol == 'UDP':
                source_port = random.randint(1024, 65535)
                dest_port = random.choice(self.common_ports)
                packet = IP(src=source_ip, dst=dest_ip) / UDP(sport=source_port, dport=dest_port)
                packet_size = len(bytes(packet))
            else:  # ICMP
                packet = IP(src=source_ip, dst=dest_ip) / ICMP()
                packet_size = len(bytes(packet))
            
            # Wyciąganie cech z pakietu
            ttl = packet[IP].ttl if IP in packet else 64
        except Exception as e:
            # Fallback jeśli Scapy nie działa - symulacja danych
            packet_size = random.randint(64, 1500)
            ttl = 64
        
        features = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'protocol': protocol,
            'source_port': source_port,
            'dest_port': dest_port,
            'packet_size': packet_size,
            'ttl': ttl,
        }
        
        return features
    
    def generate_normal_traffic(self, count=1, interval=1.0):
        """
        Generuje normalny ruch sieciowy.
        
        Args:
            count: Liczba pakietów do wygenerowania (None dla ciągłego)
            interval: Czas między pakietami w sekundach
        
        Yields:
            dict: Cechy pakietu
        """
        generated = 0
        while count is None or generated < count:
            packet = self.generate_packet()
            yield packet
            generated += 1
            if interval > 0:
                time.sleep(interval)
    
    def generate_attack_traffic(self, count=10, interval=0.1):
        """
        Generuje symulację ataku (burst traffic).
        
        Args:
            count: Liczba pakietów
            interval: Czas między pakietami (krótszy = bardziej intensywny atak)
        
        Yields:
            dict: Cechy pakietu
        """
        # Atak: wiele pakietów do tego samego portu
        target_ip = fake.ipv4()
        target_port = random.choice(self.common_ports)
        
        for i in range(count):
            packet = self.generate_packet(protocol='TCP')
            # Modyfikacja dla ataku: ten sam cel
            packet['dest_ip'] = target_ip
            packet['dest_port'] = target_port
            packet['attack_type'] = 'Port Scan'
            yield packet
            if interval > 0:
                time.sleep(interval)


# Singleton instance
generator = TrafficGenerator()

