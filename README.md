# PE 89.1 — Fundamentos de ChaCha20

**Autor:** Xavier Margalef Riestra · **Módulo:** MF0489 – Semana 2, Día 01 · **Bootcamp:** Ironhack Cybersecurity SOC

Implementación de cifrado y descifrado con **ChaCha20** (Python + PyCryptodome), análisis del **nonce**, recuperación de un mensaje con pérdida de datos mediante **sincronización del keystream** (`seek()`) e intercambio de clave **Diffie-Hellman** con cifrado XOR (RA2).

> **Enfoque MSA (mínimo, simple, auditable):** funciones pequeñas, una por parte del ejercicio, sin clases ni capas extra. Cada decisión está justificada en un ADR (`docs/adr/`) y el proceso queda registrado en `docs/WORKLOG.md`.

### Mapa rápido: rúbrica → dónde se cumple

| # | Criterio de la rúbrica | Pts | Sección | Código / prueba |
|---|---|---|---|---|
| 1 | Implementación del cifrado ChaCha20 | 2,5 | §4 | `cifrar()` · `test_parte1_coincide_con_referencia` |
| 2 | Obtención del texto cifrado | 0,8 | §4 | salida en bytes y hex |
| 3 | Análisis del nonce y sus tamaños | 1,2 | §4 | `test_nonce_invalido` · ADR-0002 |
| 4 | Implicaciones de seguridad del nonce | 1,2 | §4 | `demo_reutilizacion_nonce.py` |
| 5 | Implementación del descifrado | 2,5 | §5 | `descifrar()` · `test_parte2` |
| 6 | Calidad del código y documentación | 0,8 | todo el repo | 11 tests · ADR · WORKLOG |
| 7 | Sincronización del keystream (extra) | 1,0 | §6 | `descifrar_desde()` con `seek(8)` · `test_extra_seek` · ADR-0003 |
| RA1 | Requisitos, selección de técnicas, configuración segura vs insegura | — | §3 | — |
| RA2 | Diffie-Hellman + clave compartida + XOR | — | §7 | `diffie_hellman_xor.py` · ADR-0004 |

---

## 1. Estructura del repositorio

```
pe89-chacha20/
├── README.md                     ← enunciado resuelto + respuestas
├── requirements.txt              ← dependencia fijada (pycryptodome==3.24.1)
├── .gitignore                    ← excluye .venv, claves y secretos
├── src/
│   ├── chacha20_tool.py          ← Parte 1, Parte 2 y Extra
│   ├── demo_reutilizacion_nonce.py ← prueba práctica del riesgo de reutilizar nonce
│   └── diffie_hellman_xor.py     ← RA2: intercambio DH + cifrado XOR
├── tests/
│   ├── test_chacha20.py          ← 7 pruebas
│   └── test_diffie_hellman.py    ← 4 pruebas (unittest, sin dependencias extra)
└── docs/
    ├── WORKLOG.md                ← bitácora: pasos, dificultades y soluciones
    ├── adr/
    │   ├── 0001-libreria-pycryptodome.md
    │   ├── 0002-tamano-del-nonce.md
    │   ├── 0003-resincronizacion-con-seek.md
    │   └── 0004-diffie-hellman-xor.md
    └── evidencias/
        └── salida_ejecucion.txt  ← salida real del programa y de los tests
```

## 2. Cómo ejecutarlo

**Requisitos:** Python **3.10 o superior** (el código usa `zip(..., strict=True)`). Probado con Python 3.13 y pycryptodome 3.24.1.

Todos los comandos se lanzan desde la raíz del repositorio:

```bash
python3 -m venv .venv                 # Windows: python -m venv .venv
source .venv/bin/activate             # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python src/chacha20_tool.py              # Parte 1, Parte 2 y Extra
python src/diffie_hellman_xor.py         # RA2: Diffie-Hellman + XOR
python src/demo_reutilizacion_nonce.py   # demo del ataque por reutilización de nonce
python -m unittest discover -s tests -v  # 11 pruebas
```

> El enunciado indica `source venv/bin/activate`, pero el entorno se crea como `.venv`. La ruta correcta es `source .venv/bin/activate` (ver WORKLOG, D-01). En Windows, si PowerShell bloquea el script de activación, ejecutar antes `Set-ExecutionPolicy -Scope Process RemoteSigned` (solo afecta a esa ventana; ver WORKLOG, D-10).

---

## 3. Requisitos de seguridad y selección de técnicas (RA1)

**Cómo funciona ChaCha20, en resumen:**
1. Construye un bloque de 64 bytes (16 palabras de 32 bits) con constantes, la clave, un contador y el nonce.
2. Aplica **20 rondas** (de ahí el nombre) de la función *quarter-round*, que solo usa suma, rotación y XOR (**ARX**).
3. Suma el resultado al bloque inicial y obtiene **64 bytes de keystream**. Incrementa el contador y repite hasta cubrir el mensaje.
4. Cifra con `cifrado = texto ⊕ keystream`; para descifrar se hace la misma operación.

**Requisito que cubre ChaCha20:** la **confidencialidad**. Es un cifrado **simétrico** (misma clave para cifrar y descifrar) y **de flujo** (genera un keystream y hace XOR byte a byte). Se basa en operaciones **ARX** (suma, rotación y XOR), que son rápidas en software y no dependen de tablas. Por eso no sufre ataques de tiempo por caché como las implementaciones de AES sin aceleración por hardware.

**Cuándo elegirlo frente a AES:** en dispositivos sin instrucciones AES-NI (IoT, móviles, ARM antiguos) es más rápido y seguro. Con AES-NI, AES-GCM y ChaCha20-Poly1305 son equivalentes en seguridad.

**Comparación entre configuraciones inseguras y seguras:**

| Aspecto | ❌ Configuración insegura | ✅ Configuración segura |
|---|---|---|
| Nonce | Reutilizar (clave, nonce) — como hace el enunciado entre Parte 1 y 2 | Nonce único por mensaje (contador) o aleatorio de 24 bytes (XChaCha20) |
| Integridad | ChaCha20 solo | ChaCha20-Poly1305 (AEAD) |
| Clave | Escrita en el código, sin rotación | Gestor de secretos, rotación periódica, 256 bits de un CSPRNG |
| Aleatoriedad | `random` | `secrets` / `get_random_bytes` |
| Intercambio de clave | Enviar la clave por el mismo canal | Diffie-Hellman/ECDHE **autenticado** (§7) |
| Librería | `pycrypto` (abandonada) o cripto hecha a mano | `pycryptodome` mantenida y con versión fijada |

---

## 4. Parte 1 — Cifrado

**Parámetros:** texto plano `Este es un mensaje secreto que quiero cifrar`, clave de 32 bytes y nonce de 8 bytes (los indicados en el enunciado).

### ¿Cuál es el texto cifrado resultante?

```
Bytes: b'Ehq0\x83\xcb\x8fo\xab\xed\xd0S\x06\xcc\xbb\xecw\xe9\xec(\x1f\xc5E\xdb\x88\x18`W\xc3yQn\xad3\xec.\x08\x92\x9f\x92\xb8w\x8a\r'
Hex:   4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057c379516ead33ec2e08929f92b8778a0d
```

Coincide byte a byte con el valor de referencia del "Código P1" (verificado por el test `test_parte1_coincide_con_referencia`). Ocupa 44 bytes, igual que el texto plano: un cifrado de flujo **no añade relleno (padding)**, a diferencia de AES-CBC.

### ¿Para qué sirve el nonce?

El nonce (*number used once*) es un valor **público, no secreto**, que se combina con la clave para generar el keystream. Su función es que **la misma clave produzca un keystream diferente en cada mensaje**. Sin nonce, cifrar dos mensajes con la misma clave daría el mismo keystream. El nonce viaja en claro junto al mensaje cifrado; lo que nunca debe hacerse es **repetirlo con la misma clave**.

### ¿Qué tamaño tiene el nonce utilizado?

**8 bytes (64 bits).** Es la variante **original de Bernstein (2008)**. En ella el bloque interno de 64 bytes reparte 32 bytes para la clave, 16 para constantes, **8 para el contador** y **8 para el nonce**.

### ¿Se puede usar un nonce de mayor tamaño (12 o 16 bytes)?

| Tamaño | ¿Lo acepta PyCryptodome? | Variante | Contador | Máx. datos por (clave, nonce) |
|---|---|---|---|---|
| 8 bytes | ✅ Sí | ChaCha20 original (DJB) | 64 bits | ~2⁷⁰ bytes (prácticamente ilimitado) |
| **12 bytes** | ✅ Sí | **ChaCha20 IETF (RFC 8439)**, la de TLS 1.3 | 32 bits | **256 GiB** |
| 16 bytes | ❌ No (`ValueError`) | — | — | — |
| 24 bytes | ✅ Sí | **XChaCha20**: HChaCha20 deriva una subclave con los 16 primeros bytes; los 8 restantes van a la variante de 12 bytes | 32 bits | 256 GiB |

- **12 bytes:** sí. Se gana espacio para el nonce a costa de reducir el contador.
- **16 bytes:** no. La librería lo rechaza (comprobado con el test `test_nonce_invalido`). Los 16 bytes son la suma de contador y nonce del bloque, no un tamaño de nonce válido.
- **24 bytes:** sí, mediante XChaCha20. Comprobado en el código fuente de PyCryptodome (`Crypto/Cipher/ChaCha20.py`): con 24 bytes aplica HChaCha20 y continúa con la variante de 12 bytes.

### ¿Qué implicaciones de seguridad tiene un nonce más grande?

Lo importante no es "más grande = más cifrado", porque **la fuerza criptográfica la da la clave (256 bits) y no cambia**. El tamaño del nonce determina **cuántos mensajes se pueden cifrar con la misma clave sin riesgo de repetir nonce**:

- **Nonce aleatorio de 8 bytes (64 bits):** por la *paradoja del cumpleaños*, hacia **2³² ≈ 4.000 millones de mensajes** la probabilidad de repetir un nonce ya es del 50 %, y el riesgo deja de ser despreciable mucho antes. Con nonces aleatorios es demasiado justo; solo es seguro con un **contador** que nunca se repita.
- **12 bytes (96 bits):** el 50 % de colisión sube a ~2⁴⁸ mensajes. Con nonces aleatorios, la recomendación de NIST (SP 800-38D, para el caso análogo de GCM) es no superar **2³² mensajes por clave**. Además, el contador de 32 bits limita cada mensaje a **256 GiB**: si se supera, el contador da la vuelta y **se reutiliza keystream**.
- **24 bytes (XChaCha20):** con 192 bits, **los nonces se pueden generar aleatoriamente** (`get_random_bytes(24)`) sin preocuparse por colisiones. Es la opción más segura y simple cuando no hay forma fiable de llevar un contador (varios servidores, reinicios, dispositivos IoT…). A cambio tiene un coste mínimo (un cálculo HChaCha20 extra para derivar la subclave) y menor interoperabilidad, porque TLS usa la versión de 12 bytes.

**Conclusión:** un nonce más grande **reduce el riesgo operativo** (error humano o de diseño al generar nonces), no aumenta la fuerza del algoritmo. Ver **ADR-0002**.

### ¿Qué riesgos hay si se reutiliza la misma clave y el mismo nonce?

Es el **error más grave** que se puede cometer con un cifrado de flujo, porque **se genera exactamente el mismo keystream**:

```
C1 = P1 ⊕ K
C2 = P2 ⊕ K
C1 ⊕ C2 = P1 ⊕ P2      ← la clave se cancela
```

Consecuencias:

1. **Pérdida de confidencialidad sin necesidad de romper la clave.** Si el atacante conoce o adivina un mensaje (cabeceras HTTP, plantillas, "Estimado cliente…"), recupera el otro: `P2 = C1 ⊕ C2 ⊕ P1`.
2. **Fuga visible a simple vista:** los bytes iguales en los textos planos producen bytes iguales en los cifrados.
3. **Manipulación (maleabilidad):** sin integridad, un atacante puede cambiar bits del cifrado y cambia los mismos bits del texto plano descifrado.
4. **Con ChaCha20-Poly1305 es aún peor:** permite al atacante recuperar la clave de autenticación Poly1305 y **falsificar mensajes**.

**Demostración real con los datos de este ejercicio.** El enunciado cifra los mensajes de la Parte 1 y la Parte 2 con la misma clave y el mismo nonce. `src/demo_reutilizacion_nonce.py` muestra que:

```
Bytes iniciales identicos en C1 y C2: 38
P2 recuperado SIN la clave: Este es un mensaje secreto que quiero que de
```

Solo con los dos cifrados y conociendo el texto de la Parte 1, se recupera la Parte 2 **sin usar la clave**. Es lo mismo que pasó en casos reales como **WEP** (IV de 24 bits que se repetía), **KRACK en WPA2** (forzaba la reinstalación del nonce) o la **reutilización de nonce en AES-GCM** detectada en servidores HTTPS (Böck et al., 2016).

### Diferencias entre ChaCha20 y ChaCha20-Poly1305

| | ChaCha20 | ChaCha20-Poly1305 (AEAD, RFC 8439) |
|---|---|---|
| Confidencialidad | ✅ | ✅ |
| **Integridad** | ❌ | ✅ etiqueta (*tag*) Poly1305 de 16 bytes |
| **Autenticidad** | ❌ | ✅ solo quien tiene la clave genera un tag válido |
| Datos asociados (AAD) | ❌ | ✅ autentica cabeceras sin cifrarlas |
| Si el cifrado se modifica | Descifra basura **sin avisar** | `decrypt_and_verify()` lanza **ValueError** |
| Uso real | Bloque de construcción | **TLS 1.3, WireGuard, OpenSSH**, QUIC/HTTP/3 |

ChaCha20 solo garantiza que **nadie lea** el mensaje; ChaCha20-Poly1305 garantiza además que **nadie lo haya modificado** y que **viene de quien tiene la clave**. En la triada CIA, ChaCha20 cubre la **C**; con Poly1305 se cubre también la **I**.

**En un sistema real siempre se usa la versión AEAD** (ChaCha20-Poly1305 o AES-GCM). Este ejercicio usa ChaCha20 "a pelo" porque es didáctico.

---

## 5. Parte 2 — Descifrado

### ¿Cuál es el texto plano resultante?

```
Este es un mensaje secreto que quiero que descifres
```

**Lógica:** en un cifrado de flujo descifrar es la misma operación que cifrar (`P = C ⊕ K`), así que basta con regenerar el mismo keystream con la misma clave y el mismo nonce. El punto crítico es **crear un objeto `ChaCha20.new()` nuevo**. El objeto que ya se usó para cifrar tiene el contador interno avanzado, y PyCryptodome directamente no deja usarlo para descifrar: lanza `TypeError` (ver WORKLOG, D-03).

---

## 6. Extra — Sincronización del keystream

### ¿Cuál es el texto plano resultante?

```
saje ha sufrido un error en la transmision
```

El mensaje original sería `Este men` + `saje ha sufrido un error en la transmision`. Los **8 primeros bytes se han perdido** y no se pueden recuperar.

**Método utilizado:** `cipher.seek(8)`.

**Procedimiento y justificación:**

1. ChaCha20 genera el keystream como una secuencia determinista: el byte *i* del keystream depende solo de (clave, nonce, *i*).
2. Si el receptor empieza a descifrar desde el byte 0 pero el primer byte recibido es en realidad el byte 8, aplica el keystream equivocado. Todo sale basura (comprobado por el test `test_extra_sin_seek_falla`).
3. `seek(8)` **adelanta el contador interno** hasta el byte 8 del keystream: bloque 0, desplazamiento 8 dentro del bloque de 64 bytes. Así se vuelve a alinear con el emisor.
4. A partir de ahí, `decrypt()` recupera el texto correctamente.

**¿Por qué `seek()` y no descifrar 8 bytes de relleno y descartarlos?** Ambas opciones funcionan, pero `seek()` es la API diseñada para esto. Es más explícita (deja claro *por qué* se salta) y escala a desplazamientos grandes sin generar keystream inútil. Esta propiedad de **acceso aleatorio** es la misma que permite descifrar un fragmento de un archivo o vídeo sin procesar todo lo anterior. Ver **ADR-0003**.

**Observación de seguridad:** que un error de transmisión no se detecte y solo "rompa" una parte del mensaje es justo la falta de integridad de ChaCha20. Con ChaCha20-Poly1305 el mensaje truncado se **rechazaría entero** (tag inválido), que es el comportamiento seguro. La recuperación parcial debe gestionarla el protocolo de transporte (TCP, retransmisión), no la capa criptográfica.

---

## 7. RA2 — Intercambio Diffie-Hellman + XOR

La introducción de la práctica evalúa el **RA2 - C2** así: *"ejecución de un intercambio Diffie–Hellman, obtención de una clave compartida y su utilización para cifrar y descifrar un mensaje mediante XOR"*. Se implementa en `src/diffie_hellman_xor.py`, solo con la librería estándar.

**Problema que resuelve:** ChaCha20 necesita que emisor y receptor tengan **la misma clave**. ¿Cómo se la pasan sin que nadie la vea por el camino? Diffie-Hellman permite **acordar un secreto común enviando solo valores públicos**.

```
Público:  p (primo 2048 bits, RFC 3526)  y  g = 2
Alice:    a secreto  →  envía A = gᵃ mod p
Bob:      b secreto  →  envía B = gᵇ mod p
Alice:    s = Bᵃ mod p  ┐
Bob:      s = Aᵇ mod p  ┘  mismo s = gᵃᵇ mod p
Atacante: ve p, g, A, B  →  calcular s requiere resolver el logaritmo discreto (inviable con 2048 bits)
```

**Uso de la clave con XOR:** el secreto `s` se convierte con **SHAKE-256** en un keystream de la misma longitud que el mensaje, y se hace `cifrado = mensaje ⊕ keystream`. Bob repite la operación con su `s` y recupera el mensaje.

Ejemplo de ejecución (los valores cambian en cada ejecución porque las claves privadas son aleatorias):

```
Secreto Alice == secreto Bob: True
Mensaje             : Este es un mensaje secreto que quiero cifrar
Cifrado XOR (hex)   : 6b1f7579ec78a461eae380f9952f276e8a17ca71c5374fa2b6cd57377c642f34...
Descifrado por Bob  : Este es un mensaje secreto que quiero cifrar
Verificacion        : OK
```

**Decisiones clave (detalle en ADR-0004):**
- **Grupo estándar RFC 3526** en vez de un primo pequeño de ejemplo, que se rompe al instante.
- **`secrets` y no `random`:** `random` es predecible y no vale para claves.
- **SHAKE-256 y no repetir la clave:** repetir la clave en XOR es reutilizar keystream, el mismo fallo que reutilizar el nonce (§4).
- **Validación de la clave pública del otro:** se rechazan los valores triviales que forzarían un secreto conocido.

**Limitación importante:** DH sin autenticación es vulnerable a **man-in-the-middle**. Un atacante en medio puede hacer un intercambio con cada parte. Por eso TLS y SSH **firman** el intercambio (certificados, claves de host).

**Relación con ChaCha20:** en TLS 1.3 y SSH, **ECDHE (X25519)** acuerda la clave y **ChaCha20-Poly1305** cifra con ella. Las dos partes de esta práctica son las dos mitades de un handshake real. ECDHE es *efímero* (clave nueva por sesión), lo que da **forward secrecy**: aunque se robe la clave del servidor, las sesiones pasadas siguen protegidas.

---

## 8. Buenas prácticas y relación con ciberseguridad

### Seguridad del propio código

| Práctica | Aplicada | Por qué |
|---|---|---|
| Entorno virtual (`.venv`) | ✅ | Aísla dependencias y evita contaminar el sistema. |
| **Versión fijada** en `requirements.txt` | ✅ | **Cadena de suministro (supply chain):** un `pip install pycryptodome` sin versión instala lo último que haya en PyPI. Fijar la versión hace la instalación **reproducible** y evita actualizaciones maliciosas o con fallos. |
| Paquete correcto (`pycryptodome`, no `pycrypto`) | ✅ | `pycrypto` está **abandonado desde 2013** y tiene CVE sin corregir (p. ej. CVE-2013-7459). Ojo también con el **typosquatting**: paquetes con nombres parecidos subidos a PyPI con malware. |
| Validación de parámetros | ✅ | `_validar_parametros()` falla pronto con un mensaje claro (*fail fast*). |
| `.gitignore` con `.env` y `*.key` | ✅ | Evita subir secretos a GitHub por accidente. |
| Tests reproducibles | ✅ | Verifican el resultado contra el valor de referencia del enunciado. |
| Clave en el código | ⚠️ Solo por el enunciado | En producción **nunca**: la clave iría en un gestor de secretos (Vault, KMS) o en una variable de entorno, y se rotaría periódicamente. |

**Mejoras posibles** (fuera del alcance de un ejercicio MSA): `pip install --require-hashes`, para verificar el hash de cada paquete; `pip-audit`, para buscar CVE en las dependencias; y usar ChaCha20-Poly1305 con nonces de 24 bytes aleatorios.

### Mapeo con marcos normativos (GRC)

| Marco | Control | Relación con el ejercicio |
|---|---|---|
| **ISO/IEC 27001:2022** | **A.8.24 Uso de la criptografía** | Definir algoritmos, longitudes de clave y **gestión del ciclo de vida de claves y nonces**. |
| ISO/IEC 27001:2022 | A.8.28 Codificación segura | Validación de entradas, no hardcodear secretos, dependencias controladas. |
| ISO/IEC 27001:2022 | A.5.21 Seguridad en la cadena de suministro TIC | Control de librerías de terceros (versión fijada, origen verificado). |
| **ENS (RD 311/2022)** | **mp.com.2 Protección de la confidencialidad** y **mp.com.3 Protección de la integridad y autenticidad** | ChaCha20 cubre mp.com.2; para mp.com.3 hace falta Poly1305. Guía **CCN-STIC-807** de algoritmos autorizados. |
| **NIST SP 800-57** | Gestión de claves | Generación, almacenamiento, rotación y destrucción de claves. |
| NIST SP 800-56A | Establecimiento de claves con logaritmo discreto | Base normativa del intercambio Diffie-Hellman de §7 (grupos aprobados, validación de claves públicas). |
| NIST SP 800-53 | SC-13 Cryptographic Protection · SC-12 Key Management | Mismo enfoque que A.8.24. |
| **RGPD art. 32** | Seguridad del tratamiento | El cifrado aparece explícitamente como medida técnica adecuada. |

### Relación con OpsMatrix Lab

`TLS_CHACHA20_POLY1305_SHA256` es una de las *cipher suites* de **TLS 1.3** que negocia Nginx en `layer2-perimeter`, y `chacha20-poly1305@openssh.com` es uno de los cifrados de **OpenSSH**, el plano de control del host. En ambos casos el intercambio de clave lo hace ECDHE (X25519), la versión moderna de lo implementado en §7. Si se quiere priorizarlo frente a AES-GCM en equipos sin aceleración AES por hardware (IoT, móviles antiguos), se configura con `ssl_conf_command Ciphersuites` en Nginx o con la directiva `Ciphers` en `sshd_config`.

---

## 9. Referencias

- Documentación de PyCryptodome, ChaCha20: <https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20.html>
- RFC 8439, *ChaCha20 and Poly1305 for IETF Protocols*
- D. J. Bernstein (2008), *ChaCha, a variant of Salsa20*
- Draft IETF *XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305*
- Böck et al. (2016), *Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS*
- RFC 3526, *More Modular Exponential (MODP) Diffie-Hellman groups for IKE* (grupo 14)
- W. Diffie y M. Hellman (1976), *New Directions in Cryptography*
