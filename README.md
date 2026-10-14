# PE 89.1 — Cifrado con ChaCha20

**Autor:** Xavier Margalef Riestra · **Módulo:** MF0489 Semana 2 · **Fecha:** 14/10/2026 · **Estado:** completado, 11/11 pruebas OK

## 1. Resumen

He implementado el cifrado y el descifrado con **ChaCha20** en Python usando PyCryptodome, he recuperado el mensaje que llega con 8 bytes perdidos y he añadido el intercambio **Diffie-Hellman** que pide el RA2. El cifrado de la Parte 1 coincide byte a byte con la referencia del enunciado. El resto lo valido con pruebas automáticas.

**Lo más importante que he encontrado:** el enunciado cifra los mensajes de la Parte 1 y la Parte 2 con la misma clave y el mismo nonce. Con eso se puede leer el segundo mensaje sin tener la clave, y lo he demostrado con un script. El fallo no está en ChaCha20, está en cómo se gestiona el nonce. Es el mismo tipo de error que tumbó WEP y que aprovechaba KRACK en WPA2.

**Dónde está cada criterio de la rúbrica:**

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
| **RA2 – Diffie-Hellman + XOR** | Las dos partes llegan a la misma clave y el mensaje se cifra y descifra bien |

## 3. Respuestas a la actividad

**¿Qué tamaño tiene el nonce?** 8 bytes (64 bits), que es la versión original de ChaCha20. El nonce sirve para que la misma clave genere un keystream distinto en cada mensaje. No es secreto, pero no se puede repetir nunca con la misma clave.

**¿Se puede usar uno más grande?** De 12 bytes sí, es el estándar RFC 8439 que usa TLS 1.3. De 16 bytes no, la librería lo rechaza (lo he probado). De 24 bytes también, con XChaCha20.

**¿Qué implica un nonce más grande?** El cifrado no es más fuerte por eso, la fuerza la da la clave de 256 bits. Lo que baja es el riesgo de repetir nonce:
- Con 8 bytes generados al azar, hacia los 4.000 millones de mensajes ya hay un 50 % de probabilidad de repetir uno. Por eso con 8 bytes hay que usar un contador.
- Con 12 bytes al azar, NIST recomienda no pasar de unos 4.000 millones de mensajes por clave. Además, cada mensaje tiene un máximo de 256 GiB.
- Con 24 bytes se puede generar el nonce al azar sin preocuparse.

**¿Qué pasa si se reutilizan clave y nonce?** Se genera el mismo keystream, así que `C1 ⊕ C2 = P1 ⊕ P2` y la clave desaparece de la ecuación. Si alguien conoce o adivina uno de los mensajes, puede leer el otro. Además, las partes iguales de los dos mensajes se ven a simple vista en los cifrados. Si se usara Poly1305, repetir nonce permitiría incluso falsificar mensajes. Lo demuestro con los datos del enunciado en `src/demo_reutilizacion_nonce.py`.

**¿ChaCha20 o ChaCha20-Poly1305?** ChaCha20 solo da confidencialidad: si alguien toca el cifrado, al descifrar sale basura y nadie se entera. ChaCha20-Poly1305 añade una etiqueta (tag) que da integridad y autenticidad, y si el mensaje se ha modificado lo rechaza. Es la versión que se usa de verdad en TLS 1.3, SSH y WireGuard.

**¿Cómo se resincroniza el keystream? (extra)** El receptor empieza a descifrar desde el byte 0 del keystream, pero lo primero que le llega es el byte 8. Con `seek(8)` adelanto el keystream esos 8 bytes y vuelve a cuadrar con el emisor. Podría haber descifrado 8 bytes de relleno y tirarlos, pero `seek()` es el método pensado para esto y se entiende mejor qué estás haciendo (ADR-0003).

## 4. Riesgos y recomendaciones

| Riesgo | Impacto | Recomendación |
|---|---|---|
| Reutilizar el nonce (pasa en el enunciado) | Alto: se lee el mensaje sin la clave | Un nonce único por mensaje, o XChaCha20 con nonce aleatorio de 24 bytes |
| Cifrar sin integridad | Alto: se puede manipular sin que se note | Usar siempre ChaCha20-Poly1305 (AEAD) |
| Clave escrita en el código (aquí es un dato público del enunciado) | Medio | En producción, gestor de secretos y rotación de claves |
| **Cadena de suministro:** dependo de una librería de terceros | Medio | Versión fijada en `requirements.txt`. Ojo con `pycrypto` (abandonada y con CVE) y con paquetes de nombre parecido (typosquatting) |
| Diffie-Hellman sin autenticar | Medio: man-in-the-middle | Firmar el intercambio: certificados en TLS y claves de host en SSH (en OpsMatrix, las Ed25519) |

## 5. Cómo encaja todo

Esta práctica es, a escala, un canal seguro de verdad: Diffie-Hellman acuerda la clave, ChaCha20 cifra con ella y Poly1305 se encargaría de que nadie la manipule. Es el mismo esquema que usan el Nginx (TLS 1.3) y el OpenSSH de mi proyecto **OpsMatrix Lab**: intercambio ECDHE autenticado y cifrado AEAD, que puede ser ChaCha20-Poly1305 o AES-GCM según lo que negocie el cliente.

La conclusión que saco es que la criptografía casi nunca falla por el algoritmo. Falla por cómo se gestionan los nonces, las claves y las dependencias de terceros. Por eso las normas lo tratan como un tema de gestión y no solo técnico:
- **ISO 27001**: A.8.24 (criptografía) y A.5.21 (cadena de suministro).
- **ENS**: mp.com.2 (confidencialidad) y mp.com.3 (integridad).
- **NIST SP 800-57**: gestión de claves.
- **RGPD**, art. 32.

## 6. Cómo comprobarlo

Hace falta Python 3.10 o superior. Todos los comandos se lanzan desde la raíz del repo.

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: python -m venv .venv  y  .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python src/chacha20_tool.py              # Partes 1, 2 y extra
python src/diffie_hellman_xor.py         # RA2
python src/demo_reutilizacion_nonce.py   # demostración del riesgo
python -m unittest discover -s tests -v  # 11 pruebas
```

**Documentación de apoyo:**
- [`docs/ANALISIS_TECNICO.md`](docs/ANALISIS_TECNICO.md): cada respuesta desarrollada a fondo.
- [`docs/adr/`](docs/adr/): las 4 decisiones de diseño, con el porqué de cada una frente a las alternativas.
- [`docs/WORKLOG.md`](docs/WORKLOG.md): los pasos que he seguido y las 12 dificultades que me he encontrado.
- [`docs/evidencias/`](docs/evidencias/): la salida real de la ejecución.
