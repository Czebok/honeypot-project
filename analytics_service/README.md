# Analytics Service – Honeypot Dashboard

Serwis analityczny wyświetlający statystyki z honeypota HTTP w formie prostego dashboardu WWW, zasilanego danymi z bazy PostgreSQL (tabela `attacks`).

---

## 1. Cel i architektura

Analytics Service jest lekką aplikacją Flask, która:

- Łączy się z tą samą bazą PostgreSQL, z której korzysta `honeypot_service`.  
- Cyklowo agreguje statystyki ataków (w tle, w osobnym wątku).  
- Udostępnia:
  - ciemny dashboard HTML pod `/`,  
  - API JSON pod `/api/stats`,  
  - prosty health‑check pod `/health`.  

Dzięki cache’owaniu danych w pamięci dashboard można odświeżać w przeglądarce co 10 sekund bez nadmiernego obciążania bazy.

Struktura katalogu:

- `app.py` – aplikacja Flask, logika cache, agregacja statystyk i szablon HTML.  
- `Dockerfile` – kontener z serwisem analitycznym.  
- `requirements.txt` – zależności Pythona.  

---

## 2. Dane wejściowe – tabela `attacks`

Serwis zakłada istnienie tabeli `attacks` w bazie (tworzonej przez `sql_utils.py` z honeypot_service). Struktura:

