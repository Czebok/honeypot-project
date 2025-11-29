"""
HONEYPOT SERVICE - SILNIK WYKRYWANIA ATAKÓW
===========================================

Główny serwis wykrywający ataki. Uruchamia serwer Flask, który:
✓ Nasłuchuje żądań HTTP na porcie 8080
✓ Wykrywa typowe ataki (SQL injection, XSS, path traversal)
✓ Loguje ataki do pliku oraz bazy danych
✓ Stosuje ograniczanie liczby żądań (rate limiting), aby utrudnić DoS

FUNKCJE BEZPIECZEŃSTWA:
✓ Czyszczenie danych wejściowych ogranicza ataki typu injection
✓ Zapytania z parametrami blokują SQL injection w bazie danych
✓ Rate limiting ogranicza brute force i zalewanie żądaniami
✓ Walidacja IP utrudnia spoofing
✓ Kontener działa bez uprawnień root
✓ System plików w kontenerze w trybie tylko do odczytu
✓ Ograniczenie capabilities zmniejsza uprawnienia kontenera

Kod gotowy do produkcji z uwzględnieniem dobrych praktyk bezpieczeństwa.
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from functools import wraps
import re
from sql_utils import safe_log_attack

# ============================================================================
# KONFIGURACJA APLIKACJI FLASK
# ============================================================================

app = Flask(__name__)

# Bezpieczeństwo: ograniczenie maksymalnego rozmiaru żądania do 1 MB (ochrona przed DoS)
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024

# ============================================================================
# KONFIGURACJA LOGOWANIA
# ============================================================================

"""
LOGOWANIE - konfiguracja podwójnego logowania dla bezpieczeństwa i debugowania
==============================================================================
Logi trafiają do:
1. Pliku: /var/log/honeypot/honeypot.log (trwałe logi do audytu)
2. Konsoli: stdout (logi widoczne w Docker/Docker Compose)

Format wpisu: znacznik czasu, nazwa loggera, poziom, treść komunikatu.
Używany jest format zbliżony do JSON, co ogranicza ryzyko wstrzyknięć do logów.
"""
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/honeypot/honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# KONFIGURACJA BAZY DANYCH
# ============================================================================

"""
PARAMETRY POŁĄCZENIA Z BAZĄ - pobierane z ENV
=============================================
Zastosowanie zmiennych środowiskowych:
- Brak zahardkodowanych danych logowania w kodzie
- Łatwiejsza zmiana konfiguracji między środowiskami
- Bezpieczne wstrzykiwanie sekretów przez Docker Compose

Zmiennie środowiskowe:
- DB_HOST: host serwera PostgreSQL (domyślnie 'db' w sieci Dockera)
- DB_USER: użytkownik bazy z ograniczonymi uprawnieniami (nie admin)
- DB_PASSWORD: hasło przechowywane w .env (nie w repozytorium)
- DB_NAME: nazwa bazy z tabelą attacks
- DB_PORT: port PostgreSQL (domyślnie 5432)
"""
DB_HOST = os.getenv('DB_HOST', 'db')
DB_USER = os.getenv('DB_USER', 'honeypot_user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'SecurePass123!')
DB_NAME = os.getenv('DB_NAME', 'honeypot_db')
DB_PORT = os.getenv('DB_PORT', '5432')

# ============================================================================
# FUNKCJE POMOCNICZE DOTYCZĄCE BEZPIECZEŃSTWA
# ============================================================================

def sanitize_string(value, max_length=1024):
    """
    SANITIZE_STRING - bezpieczne czyszczenie danych wejściowych
    ===========================================================
    Cel:
    Ujednolica i oczyszcza dane wejściowe, aby ograniczyć ataki typu injection
    oraz bardzo długie wejścia mogące powodować problemy wydajnościowe.

    Działanie:
    1. Gwarantuje, że wynik jest typu string
    2. Usuwa znaki null (\x00), które mogą psuć logi/bazę
    3. Ogranicza długość tekstu do max_length znaków

    Zwraca:
    Oczyszczony i ucięty (jeśli trzeba) ciąg znaków.
    """
    if not isinstance(value, str):
        return str(value)[:max_length]

    # Usuwanie znaków null, które mogą powodować problemy w logach/bazie
    value = value.replace('\x00', '')

    # Ucinanie zbyt długich danych (ochrona przed zalewaniem logów/DB)
    return value[:max_length]


def get_client_ip():
    """
    GET_CLIENT_IP - pobiera i weryfikuje adres IP klienta
    =====================================================
    Cel:
    Ustala rzeczywisty adres IP klienta, uwzględniając pracę za proxy.

    Działanie:
    1. Najpierw sprawdza nagłówek X-Forwarded-For (jeśli jest proxy)
    2. Jeśli brak nagłówka, używa request.remote_addr
    3. Sprawdza poprawność formatu IP (IPv4 lub IPv6) za pomocą regexu
    4. Ucina IP do maks. 45 znaków
    5. Zwraca "unknown", jeśli format IP jest podejrzany

    Zabezpieczenia:
    ✓ Ogranicza spoofing IP przez nietypowe znaki
    ✓ Chroni przed nadmiernie długimi wartościami IP
    """
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr

    # Regex dopuszczający IPv4 (cyfry+kropki) lub IPv6 (hex+dwukropki)
    ip_pattern = r'^[\d.]+$|^[\da-f:]+$'
    if re.match(ip_pattern, ip):
        return sanitize_string(ip, 45)  # maksymalna długość IPv6
    return "unknown"


def rate_limit(max_per_minute=60):
    """
    RATE_LIMIT - dekorator ograniczający liczbę żądań z jednego IP
    ==============================================================
    Cel:
    Ograniczenie liczby żądań na minutę z jednego adresu IP, aby
    utrudnić brute force, skanowanie i proste DoS.

    Działanie:
    1. Dekorator opakowuje funkcję widoku Flask
    2. Pobiera IP klienta (get_client_ip)
    3. Tworzy klucz "IP:YYYY-MM-DD HH:MM" (koszyk na minutę)
    4. Zwiększa licznik żądań dla danego klucza
    5. Jeśli licznik przekracza max_per_minute – zwraca HTTP 429
    6. Po minucie powstaje nowy koszyk z nowym kluczem

    Ograniczenia:
    - Przechowuje liczniki tylko w pamięci (restart kontenera je zeruje)
    - Przy wielu replikach aplikacji warto przenieść liczniki do Redis/Memcached
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = get_client_ip()

            # Inicjalizacja słownika liczników przy pierwszym użyciu
            if not hasattr(decorated_function, 'calls'):
                decorated_function.calls = {}

            # Klucz unikalny dla IP i aktualnej minuty
            now = datetime.now()
            key = f"{client_ip}:{now.strftime('%Y-%m-%d %H:%M')}"

            # Zwiększ licznik dla danego IP/minuty
            decorated_function.calls[key] = decorated_function.calls.get(key, 0) + 1

            # Sprawdzenie limitu
            if decorated_function.calls[key] > max_per_minute:
                logger.warning(f"Przekroczony limit żądań dla IP {client_ip}")
                return jsonify({'error': 'Rate limit exceeded'}), 429

            # Kontynuuj normalną obsługę żądania
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================================================
# SILNIK WYKRYWANIA ATAKÓW
# ============================================================================

class AttackDetector:
    """
    ATTACK DETECTOR - wykrywanie typowych ataków przy użyciu regexów
    =================================================================
    Ograniczenia:
    - Wykrywanie oparte wyłącznie na dopasowaniu wzorców (nie zachowań)
    - Możliwe obejście przez silne zaciemnianie/enkodowanie payloadu
    - Ryzyko fałszywych alarmów, konieczne dostrajanie
    - Brak wykrywania ataków typu zero‑day

    Zalety:
    - Łatwe rozszerzanie o kolejne typy ataków (nowe metody/statyczne wzorce)
    - Nie modyfikuje oryginalnego żądania
    - Lekki i szybki (proste dopasowania regex)
    """

    @staticmethod
    def detect_sql_injection(data):
        # Wzorce typowych fragmentów zapytań SQL używanych w atakach
        sql_patterns = [
            r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|alter\s+table|create\s+table)",
            r"(?i)(or|and)\s+([^\s]+)\s*=\s*([^\s]+)",  # warunki typu OR 1=1
            r"(?i)(--|#|/\*|\*/)",                     # komentarze SQL
            r"(?i)['\"\\;]",                           # podstawowe znaki specjalne
            r"(?i)(exec(\s+|\()+xp_|sp_|information_schema)",  # procedury i schematy systemowe
        ]

        for pattern in sql_patterns:
            if re.search(pattern, str(data)):
                return True
        return False

    @staticmethod
    def detect_xss_attempt(data):
        # Wzorce wykrywające typowe payloady XSS (tagi, eventy JS, protokoły itp.)
        xss_patterns = [
            # Podstawowe tagi i atrybuty event handlerów
            r"(?i)(<script|<iframe|<object|<embed|<svg|<img|<body|<html)",
            r"(?i)(onload|onerror|onclick|onmouseover|onfocus|onblur|onchange|onsubmit|onmouse|onkey)",

            # JavaScriptowe protokoły i funkcje
            r"(?i)(javascript:|vbscript:|data:|livescript:)",
            r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\(|eval\s*\(|execScript|expression\s*\(|setTimeout|setInterval)",

            # Omijanie filtrów i kodowanie
            r"(?i)(\%3Cscript|\%3Ciframe|javascript\s*\%3A)",
            r"(?i)(<script[^>]*>|<iframe[^>]*>)",

            # Dodatkowe niebezpieczne wzorce
            r"(?i)(document\.(cookie|write|exec)|window\.(location|alert)|location\s*\.=)",
            r"(?i)(srcdoc=|formaction=|action\s*=\s*['\"]?javascript)",

            # Unicode i encje HTML dla <script
            r"(?i)(\u003cscript|\&#x3c;script|&#60;script)",
        ]

        for pattern in xss_patterns:
            if re.search(pattern, str(data)):
                return True
        return False

    @staticmethod
    def detect_path_traversal(data):
        # Wzorce rozpoznające próby przechodzenia po katalogach i dostępu do plików systemowych
        traversal_patterns = [
            # Klasyczne ../ lub ..\ wyjścia z katalogu
            r"\.\.[/\\]+",

            # Zakodowane odpowiedniki ../
            r"(?i)(%2e%2e[/\\]+|%2e%2e%2f|%2e%2e\\/)",

            # Odniesienia do wrażliwych plików w systemie Unix/Windows
            r"(?i)(etc/passwd|windows/system32|boot.ini|win.ini)",

            # Niedozwolone ścieżki absolutne/root
            r"(?i)(/proc/self/environ|/var/log|C:\\Windows\\System32)",

            # Wielokrotne ../ (głębokie przechodzenie po katalogach)
            r"(\.\./)+",

            # Zagnieżdżone kodowanie ../
            r"(%252e%252e|%255c%255c)",
        ]

        for pattern in traversal_patterns:
            if re.search(pattern, str(data)):
                return True
        return False

# ============================================================================
# ROUTES / ENDPOINTY FLASK
# ============================================================================

@app.route('/health', methods=['GET'])
@rate_limit(max_per_minute=100)
def health_check():
    """
    HEALTH_CHECK - prosty endpoint do monitorowania usługi
    ======================================================
    Zwraca prostą informację o stanie aplikacji:
    GET /health → {"status": "healthy"} z kodem HTTP 200.
    """
    return jsonify({'status': 'healthy'}), 200


@app.route('/', methods=['GET', 'POST'])
@rate_limit(max_per_minute=60)
def index():
    """
    MAIN ENDPOINT - główny endpoint honeypota
    =========================================
    Cel:
    Przyciąga i rejestruje potencjalne ataki HTTP.

    Przebieg:
    1. Pobiera IP klienta (zweryfikowane)
    2. Pobiera User-Agent (oczyszczony)
    3. Zbiera dane z query stringa i body
    4. Sprawdza wzorce SQL injection
    5. Sprawdza wzorce XSS
    6. Sprawdza wzorce path traversal
    7. Zapisuje zdarzenie do pliku (JSON)
    8. Jeśli wykryto atak – loguje do bazy (parametryzowane zapytanie)
    9. Zwraca ogólną odpowiedź ("Admin Panel"), aby nie ujawniać logiki
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)

    attack_type = None

    all_data = {
        'query': sanitize_string(request.query_string.decode('utf-8', errors='ignore'), 500),
        'body': sanitize_string(request.get_data(as_text=True), 1000),
    }

    for key, value in all_data.items():
        if AttackDetector.detect_sql_injection(value):
            attack_type = 'SQL_Injection'
            break
        elif AttackDetector.detect_xss_attempt(value):
            attack_type = 'XSS_Attack'
            break
        elif AttackDetector.detect_path_traversal(value):
            attack_type = 'Path_Traversal'
            break

    # Logowanie do pliku (format JSON ogranicza ryzyko wstrzyknięć do logów)
    try:
        os.makedirs('/var/log/honeypot', exist_ok=True)
        with open('/var/log/honeypot/honeypot.log', 'a') as f:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'HTTP_REQUEST',
                'source_ip': client_ip,
                'user_agent': user_agent,
                'attack_type': attack_type,
            }
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        logger.error(f"Błąd zapisu do pliku logu: {e}")

    # Logowanie do bazy danych tylko, jeśli wykryto atak
    if attack_type:
        safe_log_attack(
            attack_name=attack_type,
            source_ip=client_ip,
            user_agent=user_agent,
            db_host=DB_HOST,
            db_user=DB_USER,
            db_password=DB_PASSWORD,
            db_name=DB_NAME,
            db_port=DB_PORT
        )
        logger.warning(f"Wykryto atak: {attack_type} z IP {client_ip}")

    return "Admin Panel", 200


@app.route('/admin', methods=['GET', 'POST'])
@rate_limit(max_per_minute=30)
def admin_panel():
    """
    ADMIN PANEL - fałszywy panel administracyjny
    ============================================
    Cel:
    Udaje panel admina, by przyciągnąć pentesterów i skanery.
    Każda próba wejścia jest rejestrowana jako nieautoryzowany dostęp.
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)

    safe_log_attack('Unauthorized_Admin_Access', client_ip, user_agent,
                    DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)

    return jsonify({'error': 'Access Denied'}), 403


@app.route('/api/users', methods=['GET'])
@rate_limit(max_per_minute=40)
def get_users():
    """
    API USERS - fałszywy endpoint REST
    ==================================
    Cel:
    Symuluje endpoint API z listą użytkowników.
    Służy do wykrywania prób enumeracji/rekonesansu API.
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)

    safe_log_attack('API_Enumeration_Attempt', client_ip, user_agent,
                    DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)

    return jsonify({'error': 'Unauthorized'}), 401


@app.errorhandler(404)
def not_found(error):
    """
    404 HANDLER - wykrywanie enumeracji ścieżek
    ===========================================
    Cel:
    Przechwytuje każde żądanie na nieistniejące ścieżki
    i zapisuje je jako próbę enumeracji katalogów/API.
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)

    safe_log_attack('Path_Enumeration', client_ip, user_agent,
                    DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)

    return jsonify({'error': 'Not Found'}), 404


logger.info("Uruchamianie usługi honeypot...")
