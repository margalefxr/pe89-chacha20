# PE 89.1 — Fundamentos de ChaCha20

**Autor:** Xavier Margalef Riestra · **Módulo:** MF0489 Semana 2 · **Fecha:** 14/10/2026

## Resumen

| | |
|---|---|
| **Objetivo** | Cifrar y descifrar con ChaCha20 (Python + PyCryptodome), analizar el nonce y resincronizar el keystream tras una pérdida de datos |
| **Alcance** | Partes 1 y 2, extra de sincronización y RA2 (Diffie-Hellman + XOR) |
| **Resultado** | Todo completado. El cifrado coincide con la referencia del enunciado y pasan las 11 pruebas |
| **Observación** | Las Partes 1 y 2 usan la misma clave y el mismo nonce, y con eso se puede leer la Parte 2 sin la clave. Lo demuestro en el criterio 4 |

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

La función `cifrar()` de `src/chacha20_tool.py` crea el objeto `ChaCha20.new(key, nonce)` con la clave de 32 bytes y el nonce de 8 bytes del enunciado y cifra el texto. Antes de nada valida el tamaño de la clave y del nonce, para que si algo está mal falle al principio con un mensaje claro y no a mitad de proceso.

He usado PyCryptodome porque es la que pide el enunciado, está mantenida y tiene `seek()`, que hace falta para el extra. Descarto `pycrypto` porque está abandonada desde 2013 y tiene CVE sin corregir, y descarto implementar ChaCha20 a mano porque la regla de oro es no hacerte tu propia criptografía (ADR-0001).

## 2. Obtención del texto cifrado

```
Texto plano : Este es un mensaje secreto que quiero cifrar
Bytes       : b'Ehq0\x83\xcb\x8fo\xab\xed\xd0S\x06\xcc\xbb\xecw\xe9\xec(\x1f\xc5E\xdb\x88\x18`W\xc3yQn\xad3\xec.\x08\x92\x9f\x92\xb8w\x8a\r'
Hex         : 4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057c379516ead33ec2e08929f92b8778a0d
```

Coincide byte a byte con la referencia del "Código P1". Mide 44 bytes, lo mismo que el texto plano: al ser un cifrado de flujo no añade relleno, a diferencia de un cifrado de bloque como AES-CBC.

## 3. Análisis del nonce y sus tamaños

La función del nonce es que la misma clave genere un keystream distinto en cada mensaje. No es secreto, viaja en claro, pero con la misma clave no se puede repetir nunca.

| Tamaño | ¿PyCryptodome lo acepta? | Variante | Límite por mensaje |
|---|---|---|---|
| **8 bytes** (el usado) | Sí | ChaCha20 original (Bernstein) | Prácticamente ilimitado |
| 12 bytes | Sí | ChaCha20 IETF (RFC 8439), el de TLS 1.3 | 256 GiB |
| 16 bytes | **No** (`ValueError`, probado) | — | — |
| 24 bytes | Sí | XChaCha20 | 256 GiB |

La diferencia entre 8 y 12 bytes está en cómo se reparte el bloque interno: con 8 bytes hay 8 para el contador y 8 para el nonce; con 12 bytes se gana espacio de nonce pero el contador se queda en 4 bytes, y de ahí sale el límite de 256 GiB por mensaje.

## 4. Implicaciones de seguridad del nonce

**Tamaño.** Aquí es fácil pensar que un nonce más grande hace el cifrado más fuerte, pero no: la fuerza la da la clave de 256 bits. Lo que cambia es el riesgo de que el nonce se repita.
- **8 bytes aleatorios:** hacia unos 4.000 millones de mensajes ya hay un 50 % de probabilidad de repetir uno, así que con 8 bytes hay que tirar de contador.
- **12 bytes aleatorios:** NIST recomienda no pasar de unos 4.000 millones de mensajes por clave.
- **24 bytes aleatorios:** se puede generar al azar sin riesgo práctico de repetición. Es la opción más cómoda cuando no puedes garantizar un contador (varios servidores, reinicios…).

**Reutilización.** Con la misma clave y el mismo nonce sale exactamente el mismo keystream, así que `C1 ⊕ C2 = P1 ⊕ P2` y la clave se anula. Si alguien conoce o adivina uno de los mensajes, lee el otro, y además las partes iguales de los dos mensajes se ven a simple vista en los cifrados. Con Poly1305 todavía es peor, porque se podrían falsificar mensajes.

Lo curioso es que el propio ejercicio cae en esto: las Partes 1 y 2 usan la misma clave y el mismo nonce. Con `src/demo_reutilizacion_nonce.py` recupero la Parte 2 sin usar la clave, solo con los dos cifrados y el texto de la Parte 1. Es el mismo tipo de fallo que tenía WEP.

**ChaCha20 frente a ChaCha20-Poly1305.** ChaCha20 solo da confidencialidad: si alguien modifica el cifrado, al descifrar sale basura y nadie se entera. Poly1305 añade una etiqueta de 16 bytes que da integridad y autenticidad, y si el mensaje se ha tocado lo rechaza. Por eso en el mundo real (TLS 1.3, SSH, WireGuard) siempre se usa la versión con Poly1305.

## 5. Implementación del descifrado

`descifrar()` regenera el mismo keystream con la misma clave y el mismo nonce y vuelve a aplicar XOR. Un detalle que me encontré: hay que crear un objeto `ChaCha20.new()` nuevo, porque el que has usado para cifrar tiene el contador avanzado y PyCryptodome no te deja reutilizarlo para descifrar (lanza `TypeError`).

```
Texto plano resultante: Este es un mensaje secreto que quiero que descifres
```

## 6. Calidad del código y documentación

- Tres funciones pequeñas en `src/chacha20_tool.py`, una por parte, documentadas y sin clases que no hacen falta.
- 11 pruebas con `unittest` (librería estándar, sin dependencias extra), incluidos los casos de error: nonce de 16 bytes, clave inválida y keystream desalineado.
- La dependencia está fijada en `requirements.txt` (`pycryptodome==3.24.1`). Esto es algo que no se suele tener en cuenta: una librería de terceros es **cadena de suministro**. Si no fijas la versión, instalas lo último que haya en PyPI sin control, y también hay que vigilar los paquetes con nombre parecido (typosquatting).
- La clave está escrita en el código a propósito: es un dato público del enunciado y así el resultado es reproducible. En un caso real iría en un gestor de secretos, no en el código.
- Las decisiones están en `docs/adr/`, los pasos y las dificultades en `docs/WORKLOG.md` y la salida real en `docs/evidencias/`.

## 7. Sincronización del keystream (extra)

Se han perdido los 8 primeros bytes del cifrado. El receptor empieza a descifrar desde el byte 0 del keystream, pero lo primero que le llega corresponde al byte 8, así que todo sale mal.

`descifrar_desde()` usa **`seek(8)`** para adelantar el keystream esos 8 bytes y volver a cuadrar con el emisor:

```
Sin seek(8): b'\xad\xf9\x9f\x0e\xe0dU...'  (basura)
Con seek(8): saje ha sufrido un error en la transmision
```

Los 8 bytes perdidos ("Este men") no se pueden recuperar. He elegido `seek()` en lugar de descifrar 8 bytes de relleno y tirarlos porque es el método pensado justo para esto y se entiende mejor lo que haces (ADR-0003).

Y aquí se ve otra vez la falta de integridad de ChaCha20: el error de transmisión no se detecta. Con Poly1305 el mensaje se rechazaría entero.

---

## Ampliación: Diffie-Hellman + XOR (RA2)

La introducción evalúa el RA2 con un intercambio Diffie-Hellman, aunque no sale en la rúbrica. Lo he implementado en `src/diffie_hellman_xor.py` solo con la librería estándar:
- **Grupo de 2048 bits de RFC 3526**, y no un primo pequeño de ejemplo, que se rompe al momento.
- **Claves privadas con `secrets`**, y no con `random`, que es predecible.
- **Keystream derivado con SHAKE-256**, para no repetir la clave en el XOR. Repetirla sería el mismo fallo que reutilizar el nonce.

Las dos partes llegan a la misma clave y el mensaje se cifra y descifra bien (4 pruebas, ADR-0004). El límite es que, si el intercambio no está autenticado, es vulnerable a man-in-the-middle.

## Relación con otros temas

- **Arquitectura:** si juntas las piezas tienes un canal seguro de verdad: Diffie-Hellman acuerda la clave y ChaCha20-Poly1305 cifra. Es el mismo esquema que el TLS 1.3 de Nginx y el SSH de mi proyecto OpsMatrix Lab, donde las claves Ed25519 son las que autentican el intercambio y cubren el man-in-the-middle.
- **GRC:** todos los fallos que han salido son de gestión, no del algoritmo: nonces repetidos, claves en el código y dependencias de terceros sin control. Encajan con:
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

Si quieres el desarrollo completo de cada punto, está en [`docs/ANALISIS_TECNICO.md`](docs/ANALISIS_TECNICO.md).
