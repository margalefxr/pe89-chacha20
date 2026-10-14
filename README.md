# PE 89.1 — Fundamentos de ChaCha20

**Autor:** Xavier Margalef Riestra · **Módulo:** MF0489 Semana 2 · **Fecha:** 14/10/2026

## Resumen

| | |
|---|---|
| **Objetivo** | Cifrar y descifrar con ChaCha20 (Python + PyCryptodome), analizar el nonce y resincronizar el keystream tras una pérdida de datos |
| **Alcance** | Partes 1 y 2, extra de sincronización y RA2 (Diffie-Hellman + XOR) |
| **Resultado** | Todo completado. El cifrado coincide con la referencia del enunciado y 11/11 pruebas OK |
| **Observación** | Las Partes 1 y 2 reutilizan clave y nonce; se demuestra que permite leer la Parte 2 sin la clave (criterio 4) |

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

`src/chacha20_tool.py` → `cifrar()` crea un objeto `ChaCha20.new(key, nonce)` con la clave de 32 bytes y el nonce de 8 bytes del enunciado y cifra el texto. Antes valida los tamaños de clave y nonce para fallar con un mensaje claro si no son correctos.

Se usa PyCryptodome porque lo pide el enunciado, está mantenida y tiene `seek()`. Se descartan `pycrypto` (abandonada, con CVE) e implementar ChaCha20 a mano (ADR-0001).

## 2. Obtención del texto cifrado

```
Texto plano : Este es un mensaje secreto que quiero cifrar
Bytes       : b'Ehq0\x83\xcb\x8fo\xab\xed\xd0S\x06\xcc\xbb\xecw\xe9\xec(\x1f\xc5E\xdb\x88\x18`W\xc3yQn\xad3\xec.\x08\x92\x9f\x92\xb8w\x8a\r'
Hex         : 4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057c379516ead33ec2e08929f92b8778a0d
```

Coincide byte a byte con la referencia del "Código P1". Mide 44 bytes, igual que el texto plano, porque un cifrado de flujo no añade relleno.

## 3. Análisis del nonce y sus tamaños

**Función:** el nonce hace que la misma clave genere un keystream distinto en cada mensaje. Es público, pero no se puede repetir con la misma clave.

| Tamaño | ¿PyCryptodome lo acepta? | Variante | Límite por mensaje |
|---|---|---|---|
| **8 bytes** (el usado) | Sí | ChaCha20 original (Bernstein) | Prácticamente ilimitado |
| 12 bytes | Sí | ChaCha20 IETF (RFC 8439), el de TLS 1.3 | 256 GiB |
| 16 bytes | **No** (`ValueError`, probado) | — | — |
| 24 bytes | Sí | XChaCha20 | 256 GiB |

Con 8 bytes el bloque interno reparte 8 bytes para el contador y 8 para el nonce. Con 12 bytes se gana espacio de nonce a costa de un contador más pequeño.

## 4. Implicaciones de seguridad del nonce

**Tamaño:** un nonce más grande no hace el cifrado más fuerte (eso lo da la clave de 256 bits); lo que hace es reducir el riesgo de repetirlo.
- **8 bytes aleatorios:** hacia unos 4.000 millones de mensajes hay un 50 % de probabilidad de repetir uno. Hace falta un contador.
- **12 bytes aleatorios:** NIST recomienda no pasar de unos 4.000 millones de mensajes por clave.
- **24 bytes aleatorios:** se puede generar al azar sin riesgo práctico de repetición.

**Reutilización:** con la misma clave y el mismo nonce se genera el mismo keystream, así que `C1 ⊕ C2 = P1 ⊕ P2` y la clave se anula. Quien conozca un mensaje lee el otro, y las partes iguales se ven a simple vista en los cifrados. Con Poly1305, además, se podrían falsificar mensajes.

El propio ejercicio lo hace (Partes 1 y 2). `src/demo_reutilizacion_nonce.py` recupera la Parte 2 sin la clave, solo con los dos cifrados y el texto de la Parte 1. Es el mismo fallo que tenía WEP.

**ChaCha20 frente a ChaCha20-Poly1305:** ChaCha20 solo da confidencialidad; si se modifica el cifrado, sale basura sin aviso. Poly1305 añade una etiqueta de 16 bytes que da integridad y autenticidad, y rechaza cualquier mensaje alterado. En la práctica (TLS 1.3, SSH, WireGuard) siempre se usa la versión con Poly1305.

## 5. Implementación del descifrado

`descifrar()` regenera el mismo keystream con la misma clave y nonce y aplica XOR. Hay que crear un objeto `ChaCha20.new()` nuevo: el usado para cifrar tiene el contador avanzado y PyCryptodome no permite reutilizarlo para descifrar (`TypeError`).

```
Texto plano resultante: Este es un mensaje secreto que quiero que descifres
```

## 6. Calidad del código y documentación

- Tres funciones pequeñas en `src/chacha20_tool.py`, una por parte, documentadas y sin clases innecesarias.
- 11 pruebas con `unittest` (librería estándar), incluidos casos de error: nonce de 16 bytes, clave inválida y keystream desalineado.
- Dependencia fijada en `requirements.txt` (`pycryptodome==3.24.1`). Es una librería de terceros, así que es un punto de **cadena de suministro**: fijar la versión evita instalar sin control una versión nueva o un paquete de nombre parecido (typosquatting).
- La clave está en el código porque es un dato público del enunciado y así el resultado es reproducible. En un caso real iría en un gestor de secretos.
- Decisiones en `docs/adr/`, pasos y dificultades en `docs/WORKLOG.md` y salida real en `docs/evidencias/`.

## 7. Sincronización del keystream (extra)

Se han perdido los 8 primeros bytes del cifrado. El receptor descifra desde el byte 0 del keystream, pero lo primero que le llega corresponde al byte 8, así que todo sale mal.

`descifrar_desde()` usa **`seek(8)`** para adelantar el keystream esos 8 bytes y volver a cuadrar con el emisor:

```
Sin seek(8): b'\xad\xf9\x9f\x0e\xe0dU...'  (basura)
Con seek(8): saje ha sufrido un error en la transmision
```

Los 8 bytes perdidos ("Este men") no se pueden recuperar. Se elige `seek()` en lugar de descifrar 8 bytes de relleno y descartarlos porque es el método pensado para esto y deja clara la intención (ADR-0003). Que el error no se detecte demuestra la falta de integridad de ChaCha20: con Poly1305 el mensaje se rechazaría entero.

---

## Ampliación: Diffie-Hellman + XOR (RA2)

La introducción evalúa el RA2 con un intercambio Diffie-Hellman, aunque no aparece en la rúbrica. `src/diffie_hellman_xor.py` lo implementa con la librería estándar:
- Grupo de 2048 bits de RFC 3526.
- Claves privadas generadas con `secrets`.
- Keystream derivado con SHAKE-256 para no repetir la clave en el XOR, que sería el mismo fallo que reutilizar el nonce.

Las dos partes obtienen la misma clave y el mensaje se cifra y descifra bien (4 pruebas, ADR-0004). Su límite es que, sin autenticar el intercambio, es vulnerable a man-in-the-middle.

## Relación con otros temas

- **Arquitectura:** Diffie-Hellman acuerda la clave y ChaCha20-Poly1305 cifra; es el mismo esquema que el TLS 1.3 de Nginx y el SSH de mi proyecto OpsMatrix Lab, donde las claves Ed25519 autentican el intercambio.
- **GRC:** los fallos vistos son de gestión, no del algoritmo (nonces, claves, dependencias). Encajan con:
  - ISO 27001 A.8.24 (criptografía) y A.5.21 (cadena de suministro).
  - ENS mp.com.2 y mp.com.3.
  - NIST SP 800-57.
  - RGPD art. 32.

## Cómo ejecutarlo

Python 3.10 o superior. Desde la raíz del repo:

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: python -m venv .venv  y  .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python src/chacha20_tool.py              # Partes 1, 2 y extra
python src/diffie_hellman_xor.py         # RA2
python src/demo_reutilizacion_nonce.py   # demostración de la reutilización de nonce
python -m unittest discover -s tests -v  # 11 pruebas
```

Desarrollo completo de cada punto en [`docs/ANALISIS_TECNICO.md`](docs/ANALISIS_TECNICO.md).
