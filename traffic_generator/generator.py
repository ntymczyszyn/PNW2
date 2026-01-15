"""
Generator ruchu sieciowego używający Scapy.
Generuje dwukierunkowe przepływy sieciowe.
Zapisuje pakiety do plików .pcap.
"""
import os
import random
import time
import threading
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, wrpcap, Ether, conf, Raw
from faker import Faker

# Wyłącz ostrzeżenia Scapy o MAC
conf.verb = 0

fake = Faker()

DEFAULT_PCAP_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'pcap_files')

# Import predictora (lazy load żeby nie blokować importu jeśli model nie istnieje) ~ZUZA
_predictor = None

def get_predictor():
    """Lazy load predictora."""
    global _predictor
    if _predictor is None:
        try:
            from analytic_pipline.traffic_predictor import predict_packets
            _predictor = predict_packets
        except Exception as e:
            print(f"Warning: Could not load traffic predictor: {e}")
            _predictor = lambda x: None  # Dummy function
    return _predictor


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/91.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15",
    "curl/7.68.0",
    "python-requests/2.25.1",
    "Wget/1.21",
]
HTTP_PATHS = [
    "/", "/index.html", "/api/users", "/api/data", "/login", "/logout",
    "/search", "/products", "/cart", "/checkout", "/about", "/contact",
    "/images/logo.png", "/css/style.css", "/js/app.js", "/favicon.ico",
]
CONTENT_TYPES = [
    "text/html", "application/json", "text/plain", "text/css", 
    "application/javascript", "image/png", "image/jpeg",
]


def generate_random_http_request():
    method = random.choice(["GET", "POST", "PUT", "DELETE", "HEAD"])
    path = random.choice(HTTP_PATHS)
    if random.random() > 0.7:
        path += f"?id={random.randint(1, 10000)}&page={random.randint(1, 100)}"
    
    host = fake.domain_name()
    user_agent = random.choice(USER_AGENTS)
    
    headers = f"{method} {path} HTTP/1.1\r\n"
    headers += f"Host: {host}\r\n"
    headers += f"User-Agent: {user_agent}\r\n"
    headers += f"Accept: */*\r\n"
    headers += f"Accept-Language: en-US,en;q=0.9\r\n"
    headers += f"Connection: {random.choice(['keep-alive', 'close'])}\r\n"
    
    if random.random() > 0.5:
        headers += f"X-Request-ID: {fake.uuid4()}\r\n"
    
    body = b""
    if method in ["POST", "PUT"]:
        # Losowe dane JSON
        data = {
            "id": random.randint(1, 10000),
            "name": fake.name(),
            "email": fake.email(),
            "timestamp": datetime.now().isoformat(),
        }
        import json as json_lib
        body = json_lib.dumps(data).encode()
        headers += f"Content-Type: application/json\r\n"
        headers += f"Content-Length: {len(body)}\r\n"
    
    headers += "\r\n"
    return headers.encode() + body


def generate_random_http_response():
    status_codes = [
        (200, "OK"), (201, "Created"), (204, "No Content"),
        (301, "Moved Permanently"), (302, "Found"), (304, "Not Modified"),
        (400, "Bad Request"), (401, "Unauthorized"), (403, "Forbidden"),
        (404, "Not Found"), (500, "Internal Server Error"),
    ]
    
    # Większość odpowiedzi to 200 OK
    if random.random() > 0.3:
        code, status = 200, "OK"
    else:
        code, status = random.choice(status_codes)
    
    content_type = random.choice(CONTENT_TYPES)
    
    # Generuj losową zawartość
    if content_type == "application/json":
        import json as json_lib
        body = json_lib.dumps({
            "status": "success" if code < 400 else "error",
            "data": {"id": random.randint(1, 1000), "value": fake.word()},
            "timestamp": datetime.now().isoformat(),
        }).encode()
    elif content_type == "text/html":
        body = f"<html><head><title>{fake.sentence()}</title></head><body><h1>{fake.sentence()}</h1><p>{fake.paragraph()}</p></body></html>".encode()
    else:
        body = fake.text(max_nb_chars=random.randint(50, 500)).encode()
    
    response = f"HTTP/1.1 {code} {status}\r\n"
    response += f"Content-Type: {content_type}\r\n"
    response += f"Content-Length: {len(body)}\r\n"
    response += f"Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\n"
    response += f"Server: {random.choice(['nginx/1.18.0', 'Apache/2.4.46', 'cloudflare'])}\r\n"
    response += "\r\n"
    
    return response.encode() + body


def generate_random_dns_query():
    domain = fake.domain_name()
    query_id = random.randint(0, 65535).to_bytes(2, 'big')
    flags = b'\x01\x00'  # Standard query
    qdcount = b'\x00\x01'
    ancount = b'\x00\x00'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    
    # Encode domain name
    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'
    
    qtype = random.choice([b'\x00\x01', b'\x00\x1c', b'\x00\x0f'])  # A, AAAA, MX
    qclass = b'\x00\x01'  # IN
    
    return query_id + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass


def generate_random_dns_response(query):
    # Zmień flags na response
    response = query[:2] + b'\x81\x80' + query[4:6] + b'\x00\x01' + query[8:]
    
    # Dodaj answer section
    response += b'\xc0\x0c'  # Pointer to domain name
    response += b'\x00\x01'  # Type A
    response += b'\x00\x01'  # Class IN
    response += random.randint(60, 3600).to_bytes(4, 'big')  # TTL
    response += b'\x00\x04'  # RDLENGTH
    # Random IP
    response += bytes([random.randint(1, 254) for _ in range(4)])
    
    return response


class TrafficGenerator:
    
    def __init__(self):
        self.protocols = ['TCP', 'UDP', 'ICMP']
        self.common_ports = [80, 443, 22, 21, 25, 53, 8080, 3306, 5432]
        self.packet_buffer = []  # Bufor na pakiety Scapy do zapisu
        self.pcap_folder = DEFAULT_PCAP_FOLDER
        self.packets_per_file = 50
        self.file_counter = 0
        self.is_running = False
        self.save_to_pcap = True
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
    
    def set_pcap_folder(self, folder_path):
        if folder_path:
            self.pcap_folder = folder_path
        os.makedirs(self.pcap_folder, exist_ok=True)
    
    def set_save_to_pcap(self, enabled):
        self.save_to_pcap = enabled
    
    def _save_pcap_file(self, force=False):
        with self._lock:
            if not self.packet_buffer:
                return None
            
            if not force and len(self.packet_buffer) < self.packets_per_file:
                return None
            
            os.makedirs(self.pcap_folder, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"traffic_{timestamp}_{self.file_counter}.pcap"
            filepath = os.path.join(self.pcap_folder, filename)
            
            try:
                wrpcap(filepath, self.packet_buffer)
                saved_count = len(self.packet_buffer)
                self.packet_buffer = []
                self.file_counter += 1
                return {'filepath': filepath, 'packet_count': saved_count, 'filename': filename}
            except Exception as e:
                print(f"Błąd zapisu pcap: {e}")
                return None
    
    def flush_buffer(self):
        """Wymusza zapis pozostałych pakietów do pliku."""
        if self.save_to_pcap:
            return self._save_pcap_file(force=True)
        return None
    
    def _generate_mac(self):
        return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
    
    def _generate_tcp_flow(self, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, 
                           include_data=True, service_type='http'):
        """
        Generuje kompletny przepływ TCP z handshake, danymi i zakończeniem.
        
        Returns:
            list: Lista pakietów Scapy tworzących przepływ
        """
        packets = []
        
        # Sekwencje TCP
        client_seq = random.randint(1000, 100000)
        server_seq = random.randint(1000, 100000)
        
        # 1. SYN (Client -> Server)
        syn = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=dst_port, flags='S', seq=client_seq)
        packets.append(syn)
        
        # Małe opóźnienie symulujące RTT
        time.sleep(random.uniform(0.001, 0.01))
        
        # 2. SYN-ACK (Server -> Client)
        syn_ack = Ether(src=dst_mac, dst=src_mac) / \
                  IP(src=dst_ip, dst=src_ip, ttl=64) / \
                  TCP(sport=dst_port, dport=src_port, flags='SA', 
                      seq=server_seq, ack=client_seq + 1)
        packets.append(syn_ack)
        
        time.sleep(random.uniform(0.001, 0.01))
        
        # 3. ACK (Client -> Server) - zakończenie handshake
        client_seq += 1
        ack = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=dst_port, flags='A', 
                  seq=client_seq, ack=server_seq + 1)
        packets.append(ack)
        
        server_seq += 1
        
        if include_data:
            time.sleep(random.uniform(0.001, 0.05))
            
            # 4. Dane od klienta (Request)
            if service_type == 'http' and dst_port in [80, 8080]:
                request_data = generate_random_http_request()
            else:
                request_data = bytes([random.randint(32, 126) for _ in range(random.randint(50, 200))])
            
            request = Ether(src=src_mac, dst=dst_mac) / \
                      IP(src=src_ip, dst=dst_ip, ttl=64) / \
                      TCP(sport=src_port, dport=dst_port, flags='PA', 
                          seq=client_seq, ack=server_seq) / \
                      Raw(load=request_data)
            packets.append(request)
            client_seq += len(request_data)
            
            time.sleep(random.uniform(0.001, 0.05))
            
            # 5. ACK od serwera
            ack_request = Ether(src=dst_mac, dst=src_mac) / \
                          IP(src=dst_ip, dst=src_ip, ttl=64) / \
                          TCP(sport=dst_port, dport=src_port, flags='A', 
                              seq=server_seq, ack=client_seq)
            packets.append(ack_request)
            
            time.sleep(random.uniform(0.01, 0.1))
            
            # 6. Dane od serwera (Response)
            if service_type == 'http' and dst_port in [80, 8080]:
                response_data = generate_random_http_response()
            else:
                response_data = bytes([random.randint(32, 126) for _ in range(random.randint(100, 500))])
            
            response = Ether(src=dst_mac, dst=src_mac) / \
                       IP(src=dst_ip, dst=src_ip, ttl=64) / \
                       TCP(sport=dst_port, dport=src_port, flags='PA', 
                           seq=server_seq, ack=client_seq) / \
                       Raw(load=response_data)
            packets.append(response)
            server_seq += len(response_data)
            
            time.sleep(random.uniform(0.001, 0.01))
            
            # 7. ACK od klienta
            ack_response = Ether(src=src_mac, dst=dst_mac) / \
                           IP(src=src_ip, dst=dst_ip, ttl=64) / \
                           TCP(sport=src_port, dport=dst_port, flags='A', 
                               seq=client_seq, ack=server_seq)
            packets.append(ack_response)
        
        # 8. FIN-ACK (Client -> Server)
        time.sleep(random.uniform(0.01, 0.05))
        fin = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=dst_port, flags='FA', 
                  seq=client_seq, ack=server_seq)
        packets.append(fin)
        
        time.sleep(random.uniform(0.001, 0.01))
        
        # 9. FIN-ACK (Server -> Client)
        fin_ack = Ether(src=dst_mac, dst=src_mac) / \
                  IP(src=dst_ip, dst=src_ip, ttl=64) / \
                  TCP(sport=dst_port, dport=src_port, flags='FA', 
                      seq=server_seq, ack=client_seq + 1)
        packets.append(fin_ack)
        
        time.sleep(random.uniform(0.001, 0.01))
        
        # 10. Final ACK (Client -> Server)
        final_ack = Ether(src=src_mac, dst=dst_mac) / \
                    IP(src=src_ip, dst=dst_ip, ttl=64) / \
                    TCP(sport=src_port, dport=dst_port, flags='A', 
                        seq=client_seq + 1, ack=server_seq + 1)
        packets.append(final_ack)
        
        return packets
    
    def _generate_udp_flow(self, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac):
        """
        Generuje przepływ UDP (request-response).
        
        Returns:
            list: Lista pakietów Scapy
        """
        packets = []
        
        # DNS-like flow dla portu 53
        if dst_port == 53:
            # Query - losowo generowane
            dns_query = generate_random_dns_query()
            query = Ether(src=src_mac, dst=dst_mac) / \
                    IP(src=src_ip, dst=dst_ip, ttl=64) / \
                    UDP(sport=src_port, dport=dst_port) / \
                    Raw(load=dns_query)
            packets.append(query)
            
            time.sleep(random.uniform(0.005, 0.05))
            
            # Response - losowo generowane na podstawie query
            dns_response = generate_random_dns_response(dns_query)
            response = Ether(src=dst_mac, dst=src_mac) / \
                       IP(src=dst_ip, dst=src_ip, ttl=64) / \
                       UDP(sport=dst_port, dport=src_port) / \
                       Raw(load=dns_response)
            packets.append(response)
        else:
            # Generic UDP exchange
            request_data = bytes([random.randint(32, 126) for _ in range(random.randint(20, 100))])
            request = Ether(src=src_mac, dst=dst_mac) / \
                      IP(src=src_ip, dst=dst_ip, ttl=64) / \
                      UDP(sport=src_port, dport=dst_port) / \
                      Raw(load=request_data)
            packets.append(request)
            
            time.sleep(random.uniform(0.005, 0.05))
            
            response_data = bytes([random.randint(32, 126) for _ in range(random.randint(20, 200))])
            response = Ether(src=dst_mac, dst=src_mac) / \
                       IP(src=dst_ip, dst=src_ip, ttl=64) / \
                       UDP(sport=dst_port, dport=src_port) / \
                       Raw(load=response_data)
            packets.append(response)
        
        return packets
    
    def _generate_icmp_flow(self, src_ip, dst_ip, src_mac, dst_mac):
        """
        Generuje przepływ ICMP (ping request-reply).
        
        Returns:
            list: Lista pakietów Scapy
        """
        packets = []
        icmp_id = random.randint(1, 65535)
        icmp_seq = random.randint(1, 100)
        payload = bytes([random.randint(0, 255) for _ in range(56)])  # Standard ping payload
        
        # Echo Request
        echo_request = Ether(src=src_mac, dst=dst_mac) / \
                       IP(src=src_ip, dst=dst_ip, ttl=64) / \
                       ICMP(type=8, code=0, id=icmp_id, seq=icmp_seq) / \
                       Raw(load=payload)
        packets.append(echo_request)
        
        time.sleep(random.uniform(0.001, 0.02))
        
        # Echo Reply
        echo_reply = Ether(src=dst_mac, dst=src_mac) / \
                     IP(src=dst_ip, dst=src_ip, ttl=64) / \
                     ICMP(type=0, code=0, id=icmp_id, seq=icmp_seq) / \
                     Raw(load=payload)
        packets.append(echo_reply)
        
        return packets
    
    def generate_flow(self, protocol=None):
        """
        Generuje kompletny dwukierunkowy przepływ sieciowy.
        
        Args:
            protocol: Protokół do użycia (TCP, UDP, ICMP) lub None dla losowego
        
        Returns:
            tuple: (list of scapy_packets, features_dict)
        """
        if protocol is None:
            protocol = random.choice(self.protocols)
        
        src_ip = fake.ipv4()
        dst_ip = fake.ipv4()
        src_mac = self._generate_mac()
        dst_mac = self._generate_mac()
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(self.common_ports)
        
        if protocol == 'TCP':
            packets = self._generate_tcp_flow(src_ip, dst_ip, src_port, dst_port, 
                                              src_mac, dst_mac, include_data=True)
        elif protocol == 'UDP':
            packets = self._generate_udp_flow(src_ip, dst_ip, src_port, dst_port, 
                                              src_mac, dst_mac)
        else:  # ICMP
            packets = self._generate_icmp_flow(src_ip, dst_ip, src_mac, dst_mac)
            src_port = None
            dst_port = None
        
        # Oblicz całkowity rozmiar przepływu
        total_size = sum(len(bytes(p)) for p in packets)
        
        features = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'protocol': protocol,
            'source_port': src_port,
            'dest_port': dst_port,
            'packet_count': len(packets),
            'total_size': total_size,
            'flow_type': 'bidirectional',
        }
        
        return packets, features
    
    def add_packet_to_buffer(self, scapy_packet):
        """Dodaje pakiet do bufora i zapisuje plik gdy osiągnie limit."""
        saved_file = None
        with self._lock:
            self.packet_buffer.append(scapy_packet)
            
        if self.save_to_pcap and len(self.packet_buffer) >= self.packets_per_file:
            saved_file = self._save_pcap_file()
        
        return saved_file
    
    def add_packets_to_buffer(self, packets):
        """Dodaje wiele pakietów do bufora."""
        saved_file = None
        with self._lock:
            self.packet_buffer.extend(packets)
            
        if self.save_to_pcap and len(self.packet_buffer) >= self.packets_per_file:
            saved_file = self._save_pcap_file()
        
        return saved_file
    
    def generate_normal_traffic(self, count=1, interval=1.0):
        """
        Generuje normalny ruch sieciowy z kompletnymi przepływami.
        
        Args:
            count: Liczba przepływów do wygenerowania (None dla ciągłego)
            interval: Czas między przepływami w sekundach
        
        Yields:
            tuple: (features, saved_file_info or None)
        """
        self._stop_event.clear()
        generated = 0
        
        while (count is None or generated < count) and not self._stop_event.is_set():
            packets, features = self.generate_flow()
            saved_file = self.add_packets_to_buffer(packets)
            
            # ~Z
            #prediction = self.predict_packet(packets)
            
            yield features, saved_file
            generated += 1
            if interval > 0:
                time.sleep(interval)
    
    def generate_attack_traffic(self, count=10, interval=0.1):
        """
        Generuje symulację ataku (port scan / SYN flood style).
        
        Args:
            count: Liczba pakietów ataku
            interval: Czas między pakietami (krótszy = bardziej intensywny atak)
        
        Yields:
            tuple: (features, saved_file_info or None)
        """
        # Atak: wiele SYN pakietów z różnych źródeł do tego samego celu
        target_ip = fake.ipv4()
        target_port = random.choice(self.common_ports)
        target_mac = self._generate_mac()
        packets = []
        for i in range(count):
            # Różne źródła (spoofed IPs)
            src_ip = fake.ipv4()
            src_mac = self._generate_mac()
            src_port = random.randint(1024, 65535)
            
            # SYN flood - tylko SYN pakiety bez odpowiedzi
            syn = Ether(src=src_mac, dst=target_mac) / \
                  IP(src=src_ip, dst=target_ip, ttl=64) / \
                  TCP(sport=src_port, dport=target_port, flags='S', 
                      seq=random.randint(1000, 100000))
            
            features = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': src_ip,
                'dest_ip': target_ip,
                'protocol': 'TCP',
                'source_port': src_port,
                'dest_port': target_port,
                'packet_size': len(bytes(syn)),
                'ttl': 64,
                'attack_type': 'SYN Flood / Port Scan',
                'flow_type': 'attack',
            }
            
            packets.append(syn)
            saved_file = self.add_packet_to_buffer(syn)
            yield features, saved_file
            
            if interval > 0:
                time.sleep(interval)
        # ~Z
        #prediction = self.predict_packet(packets) 

    
    def generate_dos_attack(self, count=50, interval=0.01):
        """
        Generuje symulację ataku DoS (wiele pakietów, ten sam cel).
        
        Args:
            count: Liczba pakietów
            interval: Czas między pakietami
        
        Yields:
            tuple: (features, saved_file_info or None)
        """
        target_ip = fake.ipv4()
        target_port = 80
        target_mac = self._generate_mac()
        attacker_ip = fake.ipv4()
        attacker_mac = self._generate_mac()
        
        for i in range(count):
            src_port = random.randint(1024, 65535)
            
            # HTTP flood z dużym payloadem
            payload = bytes([random.randint(32, 126) for _ in range(1400)])
            
            pkt = Ether(src=attacker_mac, dst=target_mac) / \
                  IP(src=attacker_ip, dst=target_ip, ttl=64) / \
                  TCP(sport=src_port, dport=target_port, flags='PA', 
                      seq=random.randint(1000, 100000)) / \
                  Raw(load=payload)
            
            features = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': attacker_ip,
                'dest_ip': target_ip,
                'protocol': 'TCP',
                'source_port': src_port,
                'dest_port': target_port,
                'packet_size': len(bytes(pkt)),
                'ttl': 64,
                'attack_type': 'DoS / HTTP Flood',
                'flow_type': 'attack',
            }
            
            saved_file = self.add_packet_to_buffer(pkt)
            yield features, saved_file
            
            if interval > 0:
                time.sleep(interval)

        #prediction = self.predict_packet(pkt) # ~Z

    
    def stop(self):
        """Zatrzymuje generator i zapisuje pozostałe pakiety."""
        self._stop_event.set()
        self.is_running = False
        return self.flush_buffer()
    
    def get_buffer_status(self):
        """Zwraca status bufora."""
        with self._lock:
            return {
                'buffer_size': len(self.packet_buffer),
                'packets_per_file': self.packets_per_file,
                'files_saved': self.file_counter,
                'save_enabled': self.save_to_pcap,
                'pcap_folder': self.pcap_folder
            }

    def predict_packet(self, pacaket):
        """Predykcja przepływu za pomocą załadowanego modelu."""
        predictor = get_predictor()
        if predictor:
            try:
                return predictor(pacaket)
            except Exception as e:
                print(f"Prediction error: {e}")
        return None
# Singleton instance
traffic_generator = TrafficGenerator()

