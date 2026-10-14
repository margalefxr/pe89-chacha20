# PE 89.1 — Fundamentos de ChaCha20

**Autor:** Xavier Margalef Riestra · **Módulo:** MF0489 Semana 2 · **Fecha:** 14/10/2026

## Resumen

| | |
|---|---|
| **Objetivo** | Cifrar y descifrar con ChaCha20 (Python + PyCryptodome), analizar el nonce y resincronizar el keystream |
| **Alcance** | Partes 1 y 2, extra de sincronización y RA2 (Diffie-Hellman + XOR) |
| **Resultado** | Completado. Cifrado igual a la referencia del enunciado y 11/11 pruebas OK |
| **Observación** | Las Partes 1 y 2 reutilizan clave y nonce, lo que permite leer la Parte 2 sin la clave (ver §4) |

| Criterio | Pts | Sección | Código / prueba |
|---|---|---|---|
| 1. Implementación del cifrado ChaCha20 | 2,50 | §1 | `cifrar()` · `test_parte1_coincide_con_referencia` |
| 2. Obtención del texto cifrado | 0,80 | §2 | `docs/evidencias/` |
| 3. Análisis del nonce y sus tamaños | 1,20 | §3 | `test_nonce_invalido` · ADR-0002 |
| 4. Implicaciones de seguridad del nonce | 1,20 | §4 | `demo_reutilizacion_nonce.py` |
| 5. Implementación del descifrado | 2,50 | §5 | `descifrar()` · `test_parte2` |
| 6. Calidad del código y documentación | 0,80 | §6 | 11 tests · ADR · WORKLOG |
| 7. Sincronización del keystream | 1,00 | §7 | `descifrar_desde()` · `test_extra_seek` · ADR-0003 |
| **TOTAL** | **10,00** | | |

---

## 1. Implementación del cifrado ChaCha20

`cifrar()` en `src/chacha20_tool.py`: valida el tamaño de clave (32 bytes) y nonce, crea `ChaCha20.new(key, nonce)` y cifra.

| Librería | Decisión | Motivo |
|---|---|---|
| **PyCryptodome** | ✅ Elegida | La pide el enunciado, está mantenida y tiene `seek()` |
| `pycrypto` | ❌ | Abandonada desde 2013, con CVE sin corregir |
| ChaCha20 a mano | ❌ | No se implementa criptografía propia (ADR-0001) |

## 2. Obtención del texto cifrado

**¿Cuál es el texto cifrado resultante?**

```
Bytes : b'Ehq0\x83\xcb\x8fo\xab\xed\xd0S\x06\xcc\xbb\xecw\xe9\xec(\x1f\xc5E\xdb\x88\x18`W\xc3yQn\xad3\xec.\x08\x92\x9f\x92\xb8w\x8a\r'
Hex   : 4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057c379516ead33ec2e08929f92b8778a0d
```

Coincide con la referencia del "Código P1". Son 44 bytes, igual que el texto plano, porque un cifrado de flujo no añade padding.

## 3. Análisis del nonce y sus tamaños

**¿Qué tamaño tiene el nonce utilizado?** 8 bytes (64 bits), la variante original de Bernstein.

El nonce hace que la misma clave genere un keystream distinto en cada mensaje. Es público, pero no se puede repetir con la misma clave.

**¿Se puede usar uno de 12 o 16 bytes?** 12 sí, 16 no.

| Tamaño | PyCryptodome | Variante | Contador | Límite por mensaje |
|---|---|---|---|---|
| **8 bytes** (usado) | ✅ | ChaCha20 original | 64 bits | Prácticamente ilimitado |
| 12 bytes | ✅ | IETF, RFC 8439 (TLS 1.3) | 32 bits | 256 GiB |
| 16 bytes | ❌ `ValueError` (probado) | — | — | — |
| 24 bytes | ✅ | XChaCha20 | 32 bits | 256 GiB |

## 4. Implicaciones de seguridad del nonce

**¿Qué implica usar un nonce más grande?** No sube la seguridad del cifrado, que depende de la clave de 256 bits. Reduce la probabilidad de repetir nonce.

| Nonce aleatorio | Riesgo de repetición | Recomendación |
|---|---|---|
| 8 bytes | 50 % hacia ~4.000 millones de mensajes | Usar contador, no aleatorio |
| 12 bytes | NIST: máximo ~4.000 millones de mensajes por clave | Contador o aleatorio con límite |
| 24 bytes | Despreciable | Aleatorio sin gestión de contador |

**¿Qué riesgos hay si se reutilizan clave y nonce?** Se genera el mismo keystream, así que `C1 ⊕ C2 = P1 ⊕ P2` y la clave se anula:
- Conociendo un mensaje se recupera el otro.
- Las partes iguales de ambos mensajes se ven en los cifrados.
- Con Poly1305 además se podrían falsificar mensajes.

El enunciado lo hace en las Partes 1 y 2. `src/demo_reutilizacion_nonce.py` recupera la Parte 2 sin la clave, solo con los dos cifrados y el texto de la Parte 1 (mismo fallo que WEP).

**¿Diferencias entre ChaCha20 y ChaCha20-Poly1305?**

| | ChaCha20 | ChaCha20-Poly1305 (AEAD) |
|---|---|---|
| Confidencialidad | ✅ | ✅ |
| Integridad y autenticidad | ❌ | ✅ tag de 16 bytes |
| Cifrado modificado | Descifra basura sin avisar | Lo rechaza (`ValueError`) |
| Uso real | Base | TLS 1.3, SSH, WireGuard |

## 5. Implementación del descifrado

**¿Cuál es el texto plano resultante?** `Este es un mensaje secreto que quiero que descifres`

`descifrar()` regenera el mismo keystream con la misma clave y nonce y aplica XOR. Hay que crear un objeto `ChaCha20.new()` nuevo: el usado para cifrar tiene el contador avanzado y PyCryptodome no deja reutilizarlo (`TypeError`).

## 6. Calidad del código y documentación

| Aspecto | Qué hay |
|---|---|
| Código | 3 funciones en `src/chacha20_tool.py`, una por parte, documentadas |
| Pruebas | 11 con `unittest`, incluidos errores (nonce de 16 bytes, clave inválida, keystream desalineado) |
| Supply chain | `pycryptodome==3.24.1` fijada en `requirements.txt`: evita instalar versiones sin control o paquetes de nombre parecido (typosquatting) |
| Secretos | Clave en el código porque es dato público del enunciado; en producción, gestor de secretos |
| Documentación | `docs/adr/` (decisiones), `docs/WORKLOG.md` (pasos y dificultades), `docs/evidencias/` (salida real) |

## 7. Sincronización del keystream (extra)

**¿Qué método sincroniza el keystream y cuál es el texto plano?** `seek(8)` → `saje ha sufrido un error en la transmision`

Faltan los 8 primeros bytes, así que el receptor aplica el keystream desde el byte 0 a datos que empiezan en el byte 8. `seek(8)` adelanta el keystream y vuelve a alinearlo con el emisor.

```
Sin seek(8): b'\xad\xf9\x9f\x0e\xe0dU...'   (basura)
Con seek(8): saje ha sufrido un error en la transmision
```

- Los 8 bytes perdidos ("Este men") no se recuperan.
- Se usa `seek()` en vez de descifrar 8 bytes de relleno porque es el método previsto para esto (ADR-0003).
- El error no se detecta porque ChaCha20 no tiene integridad. Con Poly1305 el mensaje se rechazaría.

---

## Extra: Diffie-Hellman + XOR (RA2)

Lo pide la introducción (RA2), no la rúbrica. `src/diffie_hellman_xor.py`, solo con librería estándar:

| Decisión | Motivo |
|---|---|
| Grupo 2048 bits RFC 3526 | Un primo pequeño de ejemplo se rompe al momento |
| `secrets` y no `random` | `random` es predecible |
| Keystream con SHAKE-256 | Repetir la clave en el XOR = reutilizar keystream |
| Validar la clave pública recibida | Evita valores triviales que fuerzan el secreto |

Resultado: las dos partes obtienen la misma clave y el mensaje se cifra y descifra bien (4 pruebas, ADR-0004). Limitación: sin autenticar el intercambio, es vulnerable a MITM.

## Relación con arquitectura y GRC

| Tema | Relación |
|---|---|
| OpsMatrix Lab | DH + AEAD es el esquema del TLS 1.3 de Nginx y del SSH del host; las claves Ed25519 autentican el intercambio y cubren el MITM |
| ISO 27001 | A.8.24 criptografía · A.5.21 cadena de suministro |
| ENS | mp.com.2 confidencialidad · mp.com.3 integridad |
| NIST / RGPD | SP 800-57 gestión de claves · RGPD art. 32 |

Los fallos que aparecen (nonce repetido, clave en el código, dependencias de terceros) son de gestión, no del algoritmo.

## Cómo ejecutarlo

Python 3.10 o superior, desde la raíz del repo:

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: python -m venv .venv  y  .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python src/chacha20_tool.py              # Partes 1, 2 y extra
python src/diffie_hellman_xor.py         # RA2
python src/demo_reutilizacion_nonce.py   # reutilización de nonce
python -m unittest discover -s tests -v  # 11 pruebas
```

Desarrollo completo en [`docs/ANALISIS_TECNICO.md`](docs/ANALISIS_TECNICO.md).
