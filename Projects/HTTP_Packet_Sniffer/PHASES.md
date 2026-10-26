# HTTP Packet Sniffer - Cerințe și Faze de Dezvoltare

Sursa: [Python Course FII - Project 16: HTTP Packet Sniffer](https://gdt050579.github.io/python-course-fii/projects_a/16.html#http-packet-sniffer)

---

## Phase 1: Raw Packet Capture
**Obiectiv:** Configurarea capturii de pachete de nivel jos folosind socket-uri Python.
- Capturarea tuturor pachetelor TCP de intrare (incoming) și de ieșire (outgoing).
- Asigurarea capturii pachetelor în timp real, fără pierderi (zero packet loss).
- **Output Funcțional:** Aplicația captează cu succes pachete TCP brute de pe interfața de rețea.

---

## Phase 2: HTTP Packet Identification
**Obiectiv:** Filtrarea pachetelor capturate pentru a identifica traficul HTTP.
- Decodarea headerelor de pachete folosind `struct` / `ctypes`.
- Separarea cererilor (requests) HTTP de restul traficului.
- **Output Funcțional:** Doar pachetele de tip HTTP request sunt afișate și procesate.

---

## Phase 3: Real-Time Display of Requests
**Obiectiv:** Afișarea cererilor HTTP într-un format structurat în consolă.
- Afișarea metodei (GET, POST etc.), URL-ului, IP-ului sursă/destinație și a timestamp-ului.
- Asigurarea lizibilității și clarității în consolă.
- **Output Funcțional:** Utilizatorii pot vizualiza cererile HTTP în timp real cu câmpuri clare.

---

## Phase 4: Request Filtering
**Obiectiv:** Implementarea filtrelor pentru cererile HTTP capturate.
- Filtrare după tipul metodei (`GET`, `POST`, `DELETE`, etc.).
- Filtrare după adresa IP sursă sau destinație.
- **Output Funcțional:** Utilizatorii pot vizualiza doar cererile care corespund filtrelor selectate.

---

## Phase 5: Detailed Request Inspection
**Obiectiv:** Permiterea inspectării detaliate a cererilor HTTP individuale.
- Afișarea headerelor complete, modului cererii, payload-ului (body) și a altor metadate.
- Furnizarea unui output structurat în consolă.
- **Output Funcțional:** Utilizatorii pot vizualiza toate detaliile oricărei cereri HTTP selectate.

---

## Phase 6: Testing, Performance, and Robustness
**Obiectiv:** Adăugarea de teste și optimizarea performanței pentru trafic de volum mare.
- Asigurarea că nu există pierderi de pachete sau blocări/crash-uri sub încărcare (high load).
- Validarea acurateței filtrelor și a corectitudinii inspecției.
- **Output Funcțional:** Sniffer stabil, de înaltă performanță, cu filtrare fiabilă și inspecție detaliată a cererilor.
