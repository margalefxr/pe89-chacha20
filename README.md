# Informe PE 89.1 — Cifrado con ChaCha20

**Autor:** Xavier Margalef Riestra · **Módulo:** MF0489 Semana 2 · **Fecha:** 14/10/2026 · **Estado:** ✅ Completado (11/11 pruebas OK)

## 1. Resumen ejecutivo

Se ha implementado el cifrado y el descifrado con **ChaCha20** (Python + PyCryptodome), se ha recuperado un mensaje dañado en la transmisión y se ha añadido el intercambio de claves **Diffie-Hellman** del RA2. El cifrado coincide byte a byte con la referencia del enunciado y el resto de resultados se validan con pruebas automáticas.

**Hallazgo principal:** el enunciado cifra dos mensajes con **la misma clave y el mismo nonce**. Se ha demostrado que eso permite leer el segundo mensaje **sin conocer la clave**. El algoritmo no falla; falla la **gestión** del nonce. Es el mismo error que rompió WEP y que explotó KRACK en WPA2.

**Dónde se cumple cada criterio de la rúbrica:**

| Criterio | Pts | Dónde | Prueba / evidencia |
|---|---|---|---|
| 1. Cifrado ChaCha20 | 2,5 | `cifrar()` | `test_parte1_coincide_con_referencia` |
| 2. Texto cifrado | 0,8 | §2 | `docs/evidencias/` |
| 3. Nonce y tamaños | 1,2 | §3 | `test_nonce_invalido` · ADR-0002 |
| 4. Seguridad del nonce | 1,2 | §3 | `demo_reutilizacion_nonce.py` |
| 5. Descifrado | 2,5 | `descifrar()` | `test_parte2` |
| 6. Código y documentación | 0,8 | todo el repo | 11 tests · ADR · WORKLOG |
| 7. Extra: sincronización | 1,0 | `descifrar_desde()` + `seek(8)` | `test_extra_seek` · ADR-0003 |
| RA2. Diffie-Hellman + XOR | — | `diffie_hellman_xor.py` | 4 tests · ADR-0004 |

## 2. Resultados

| Parte | Resultado |
|---|---|
| **P1 – Texto cifrado** (hex) | `4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057c379516ead33ec2e08929f92b8778a0d` |
| **P2 – Texto descifrado** | `Este es un mensaje secreto que quiero que descifres` |
| **Extra – Recuperado con `seek(8)`** | `saje ha sufrido un error en la transmision` (los 8 bytes perdidos, "Este men", no se pueden recuperar) |
| **RA2 – Diffie-Hellman + XOR** | Ambas partes obtienen la misma clave; el mensaje se cifra y descifra correctamente |

## 3. Respuestas a la actividad

**¿Qué tamaño tiene el nonce?** **8 bytes (64 bits)**, la versión original de ChaCha20. Su función es que una misma clave genere un flujo de cifrado (keystream) distinto en cada mensaje. Es público, pero **no debe repetirse nunca** con la misma clave.

**¿Se puede usar uno mayor?** **12 bytes: sí** (estándar RFC 8439, el que usa TLS 1.3). **16 bytes: no**; la librería lo rechaza, comprobado. **24 bytes: sí** (XChaCha20).

**¿Qué implica un nonce mayor?** No hace el cifrado más fuerte (eso lo da la clave de 256 bits): **reduce el riesgo de repetir nonce**.
- Con 8 bytes generados al azar, la probabilidad de repetición llega al 50 % hacia unos 4.000 millones de mensajes, así que exige un contador.
- Con 12 bytes aleatorios, el límite recomendado (NIST) es de unos 4.000 millones de mensajes por clave; además, cada mensaje no puede superar 256 GiB.
- Con 24 bytes se puede usar un nonce aleatorio sin preocuparse.

**¿Riesgo de reutilizar clave y nonce?** Se genera el mismo keystream. Por eso `C1 ⊕ C2 = P1 ⊕ P2` y la clave desaparece de la ecuación: quien conozca o adivine un mensaje lee el otro, y los bytes iguales en ambos mensajes se ven a simple vista en los cifrados. Con Poly1305, repetir nonce permitiría además falsificar mensajes. **Demostrado con los datos del enunciado** (`src/demo_reutilizacion_nonce.py`).

**¿ChaCha20 frente a ChaCha20-Poly1305?** ChaCha20 solo da **confidencialidad**: si alguien altera el mensaje, se descifra basura sin avisar. ChaCha20-Poly1305 añade una etiqueta (tag) que garantiza **integridad y autenticidad** y rechaza cualquier mensaje modificado. Es la versión que usan TLS 1.3, SSH y WireGuard.

**¿Cómo se resincroniza el keystream (extra)?** El receptor empezaba a descifrar con el byte 0 del keystream, pero el primer byte recibido correspondía al byte 8. `seek(8)` adelanta el keystream exactamente esos 8 bytes y vuelve a alinearlo con el emisor. Se eligió `seek()` frente a "descifrar 8 bytes de relleno y descartarlos" porque es el método diseñado para ello y deja clara la intención (ADR-0003).

## 4. Riesgos y recomendaciones

| Riesgo | Impacto | Recomendación |
|---|---|---|
| Reutilizar el nonce (presente en el enunciado) | 🔴 Alto: se lee el mensaje sin la clave | Nonce único por mensaje; XChaCha20 con nonce aleatorio de 24 bytes |
| Cifrar sin integridad | 🔴 Alto: manipulación sin detectar | Usar siempre ChaCha20-Poly1305 (AEAD) |
| Clave escrita en el código (aquí es un dato público del enunciado) | 🟠 Medio | En producción: gestor de secretos y rotación de claves |
| **Cadena de suministro**: librería de terceros | 🟠 Medio | Versión fijada en `requirements.txt`; evitar `pycrypto` (abandonada, con CVE) y paquetes con nombre parecido (typosquatting) |
| Diffie-Hellman sin autenticar | 🟠 Medio: man-in-the-middle | Firmar el intercambio: certificados en TLS, claves de host en SSH (las Ed25519 de OpsMatrix cumplen esa función) |

## 5. Visión de conjunto

La práctica reproduce, en pequeño, **un canal seguro real**: Diffie-Hellman acuerda la clave, ChaCha20 cifra con ella y Poly1305 garantizaría que nadie la manipule. Es el mismo esquema que usan el Nginx (TLS 1.3) y el OpenSSH de mi proyecto **OpsMatrix Lab**: intercambio ECDHE autenticado y cifrado AEAD, que puede ser ChaCha20-Poly1305 o AES-GCM según lo que negocie el cliente.

La lección para la dirección es que **la criptografía rara vez falla por el algoritmo; falla por cómo se gestiona**: nonces, claves y dependencias de terceros. Por eso las normas lo tratan como un control de gestión y no solo técnico:
- **ISO 27001**: A.8.24 (criptografía) y A.5.21 (cadena de suministro).
- **ENS**: mp.com.2 (confidencialidad) y mp.com.3 (integridad).
- **NIST SP 800-57**: gestión de claves.
- **RGPD**, art. 32.

## 6. Cómo verificarlo

Requiere Python 3.10 o superior. Todos los comandos se lanzan desde la raíz del repositorio.

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: python -m venv .venv  y  .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python src/chacha20_tool.py              # Partes 1, 2 y extra
python src/diffie_hellman_xor.py         # RA2
python src/demo_reutilizacion_nonce.py   # demostración del riesgo
python -m unittest discover -s tests -v  # 11 pruebas
```

**Documentación de soporte:**
- [`docs/ANALISIS_TECNICO.md`](docs/ANALISIS_TECNICO.md): desarrollo completo de cada respuesta.
- [`docs/adr/`](docs/adr/): 4 decisiones justificadas, del tipo "por qué A y no B".
- [`docs/WORKLOG.md`](docs/WORKLOG.md): pasos seguidos y 12 dificultades resueltas.
- [`docs/evidencias/`](docs/evidencias/): salida real de la ejecución.
