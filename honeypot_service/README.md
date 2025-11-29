# Honeypot Service – Attack Detection Engine

Python/Flask‑owy honeypot HTTP z logowaniem do PostgreSQL i prostym silnikiem wykrywania ataków opartym na regexach.[web:28]

---

## 1. Architektura i przegląd

Honeypot składa się z lekkiej aplikacji Flask uruchamianej w kontenerze Docker oraz bazy PostgreSQL do przechowywania zarejestrowanych zdarzeń.[web:28]  
Aplikacja nasłuchuje na porcie `8080` i udostępnia kilka endpointów imitujących panel administracyjny oraz API, których głównym celem jest przyciąganie skanerów i pentesterów.[web:11]

**Główne komponenty:**

- `app.py` – serwis webowy (Flask), silnik wykrywania ataków, rate limiting, logowanie do pliku i bazy.  
- `sql_utils.py` – bezpieczne funkcje dostępu do PostgreSQL (zapytania parametryzowane).[web:10]  
- `Dockerfile` – obraz aplikacji z dobrymi praktykami bezpieczeństwa kontenera (non‑root, fs read‑only).[web:20]  
- `requirements.txt` – zależności Pythona (Flask, psycopg2 itd.).[web:10]

---

## 2. Funkcjonalności bezpieczeństwa

Serwis implementuje kilka warstw ochrony, które łącznie zwiększają wiarygodność honeypota i utrudniają nadużycia.[web:26]

**Mechanizmy:**

- **Wykrywanie ataków:**
  - SQL injection – wzorce fragmentów zapytań SQL, komentarzy i konstrukcji typu `OR 1=1`.[web:8]
  - XSS – wykrywanie tagów `<script>`, zdarzeń JS (`onload`, `onclick`), schematów `javascript:` oraz typowych funkcji JS.[web:8]
  - Path traversal – sekwencje `../` i ich zakodowane odpowiedniki oraz odwołania do wrażliwych plików systemowych.[web:29]
- **Rate limiting** – ograniczanie liczby żądań na minutę z jednego IP, z odpowiedzią HTTP `429` po przekroczeniu limitu.[web:5]
- **Walidacja danych wejściowych** – funkcja `sanitize_string` usuwa bajty null i ucina zbyt długie ciągi, ograniczając ryzyko DoS i problemów z logami/bazą.[web:20]
- **Walidacja IP** – proste regexy dopuszczają tylko podstawowe formaty IPv4/IPv6, reszta jest mapowana na `unknown`.  
- **Bezpieczne logowanie do bazy** – wszystkie zapytania SQL używają placeholderów i osobnych parametrów, co jest standardem ochrony przed SQL injection.[web:10][web:13]
- **Twardnienie kontenera** – uruchamianie bez uprawnień root i ograniczanie capabilities zgodnie z zaleceniami bezpieczeństwa Pythona i Dockera.[web:20]

---

## 3. Endpointy HTTP

| Endpoint      | Metody      | Limit/min/IP | Opis                                                                 |
|--------------|------------|-------------|----------------------------------------------------------------------|
| `/health`    | `GET`      | 100         | Prosty check zdrowia serwisu, używany w monitoringu.                |
| `/`          | `GET,POST` | 60          | Główny honeypot; wykrywa SQLi/XSS/path traversal, loguje do pliku/DB. |
| `/admin`     | `GET,POST` | 30          | Fałszywy panel administracyjny; wszystkie próby wejścia są logowane.|
| `/api/users` | `GET`      | 40          | Fałszywe API REST do wykrywania enumeracji API.                     |
| `*` (404)    | dowolna    | —           | Każda nieistniejąca ścieżka jest logowana jako próba enumeracji.    |

Każde żądanie przechodzące przez endpoint chroniony dekoratorem `rate_limit` jest liczone w słowniku w pamięci per klucz `IP:YYYY-MM-DD HH:MM`.[web:5]  
Wykryte ataki oraz wybrane podejrzane akcje (np. wejście na `/admin`) trafiają do tabeli `attacks` w bazie PostgreSQL, skąd można je analizować w zewnętrznych narzędziach.[web:28]

---

## 4. Model danych i baza

Baza PostgreSQL zawiera główną tabelę:

TABLE attacks

id SERIAL PRIMARY KEY

attack_name VARCHAR(100) NOT NULL

source_ip VARCHAR(45) NOT NULL

user_agent VARCHAR(1024)

timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP

created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP


Tworzone są indeksy:

- `idx_attacks_timestamp` na `timestamp DESC` – szybkie zapytania po czasie.  
- `idx_attacks_source_ip` – analizy źródeł ataków i korelacja z SIEM.  
- `idx_attacks_attack_name` – statystyki typów ataków.  

Funkcja `init_database()` w `sql_utils.py` tworzy tabelę i indeksy w sposób idempotentny, więc może być bezpiecznie wywoływana przy starcie systemu.[web:15]

---

## 5. Konfiguracja i uruchomienie

### Zmienne środowiskowe

Aplikacja używa następujących zmiennych środowiskowych:

- `DB_HOST` – host PostgreSQL (np. `db`).  
- `DB_USER` – użytkownik z ograniczonymi uprawnieniami.  
- `DB_PASSWORD` – hasło (z pliku `.env` lub managera sekretów).  
- `DB_NAME` – nazwa bazy (np. `honeypot_db`).  
- `DB_PORT` – port PostgreSQL (domyślnie `5432`).  

Taki sposób konfiguracji jest zgodny z dobrymi praktykami bezpieczeństwa i ułatwia deploy w różnych środowiskach.[web:19]

### Szybki start (lokalnie)

1. Utwórz bazę PostgreSQL (lokalnie lub w kontenerze) i użytkownika z ograniczonymi uprawnieniami.[web:15]  
2. Ustaw zmienne `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_PORT`.  
3. Zainstaluj zależności:  

pip install -r requirements.txt

4. Zainicjalizuj bazę, wywołując `init_database()` z `sql_utils.py` (np. w krótkim skrypcie startowym).  
5. Uruchom serwis:  

python app.py


W środowisku kontenerowym typowym podejściem jest użycie `docker-compose` z osobnymi usługami dla honeypota i bazy, co jest spójne z praktykami z innych projektów honeypotowych.[web:28]

---

## 6. Logowanie i analiza

Serwis zapisuje logi w dwóch miejscach:

- **Plik**: `/var/log/honeypot/honeypot.log` – logi tekstowe w formacie zbliżonym do JSON (jeden wpis na linię).  
- **Baza danych**: tabela `attacks` – dane do analityki, raportów, korelacji z SIEM i budowy dashboardów (np. w Grafanie/Kibanie).[web:29]

Zalecane działania:

- Zamontowanie katalogu `/var/log/honeypot` jako wolumenu i wysyłka logów do centralnego systemu logowania.[web:29]  
- Zbudowanie prostego panelu (oddzielny serwis) korzystającego z funkcji `get_attacks()` do wizualizacji ostatnich incydentów.

---

## 7. Ograniczenia i kierunki rozwoju

**Ograniczenia:**

- Detekcja oparta wyłącznie na regexach – brak analizy behawioralnej i korelacji zdarzeń.[web:8]  
- Rate limiting trzymany w pamięci procesu – w klastrze trzeba przenieść liczniki do zewnętrznego magazynu (Redis/Memcached).[web:5]  
- Honeypot jest nisko‑interakcyjny, nie emuluje złożonych aplikacji biznesowych.[web:26]

**Możliwe rozszerzenia:**

- Integracja z Redis dla współdzielonego rate limitingu.  
- Dodanie kolejnych detektorów (RCE, LFI/RFI, specyficzne payloady narzędzi).  
- Eksport metryk w formacie Prometheus i gotowe dashboardy Grafana.  
- Integracja z systemem powiadomień (Slack/Email/Webhook) dla wybranych typów ataków.[web:11]

---