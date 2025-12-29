# Generator ruchu sieciowego

## Opis
Aplikacja do generowania i wyświetlania pakietów sieciowych w czasie rzeczywistym.

## Funkcjonalności
- Generator pakietów sieciowych używający Scapy
- Wyświetlanie pakietów w czasie rzeczywistym (Server-Sent Events)
- Symulacja normalnego ruchu
- Symulacja ataków sieciowych
- Prosty interfejs webowy (Bootstrap)

## Instalacja

1. Utwórz i aktywuj wirtualne środowisko:
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# lub
venv\Scripts\activate  # Windows
```

2. Zainstaluj zależności:
```bash
pip install -r requirements.txt
```

## Uruchomienie

1. Uruchom serwer Django:
```bash
python3 manage.py runserver
```

2. Otwórz przeglądarkę:
```
http://127.0.0.1:8000/
```

## API Endpoints

- `GET /traffic/api/packets/` - Pobierz ostatnie pakiety (JSON)
- `GET /traffic/api/stream/` - Stream pakietów w czasie rzeczywistym (SSE)
- `POST /traffic/api/start/` - Uruchom generator
- `GET /traffic/api/attack/?count=10` - Symuluj atak

## Struktura projektu

```
impl/
├── network_monitor/          # Projekt Django
│   ├── settings.py
│   └── urls.py
├── traffic_generator/        # Aplikacja generatora
│   ├── generator.py          # Generator z Scapy
│   ├── views.py              # API endpoints
│   ├── urls.py               # Routing
│   └── templates/
│       └── traffic_generator/
│           └── index.html    # Interfejs webowy
└── requirements.txt
```
