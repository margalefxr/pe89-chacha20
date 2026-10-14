# ADR-0004 — Diffie-Hellman + XOR (RA2)

- **Estado:** Aceptado
- **Fecha:** 2026-10-14

## Contexto

La introducción de la PE 89.1 evalúa el **RA2 - C2** mediante un intercambio Diffie-Hellman, la obtención de una clave compartida y su uso para cifrar y descifrar un mensaje con XOR. La Actividad y la rúbrica no lo detallan, así que se implementa la versión mínima que cumple el resultado de aprendizaje.

## Decisiones

| Punto | Opción elegida (A) | Alternativa descartada (B) | Por qué A |
|---|---|---|---|
| Librería | Solo librería estándar (`pow`, `secrets`, `hashlib`) | `cryptography` / PyCryptodome DH | Cero dependencias nuevas; el cálculo es tan corto que se ve entero (didáctico) |
| Parámetros p, g | **Grupo 14 de RFC 3526** (2048 bits, g = 2) | Primo pequeño inventado (p. ej. p = 23) | Un primo de juguete se rompe al instante; uno inventado puede ser débil. Un grupo estándar es revisado y auditado |
| Números aleatorios | `secrets` (CSPRNG) | `random` | `random` es predecible (Mersenne Twister): no sirve para claves |
| Del secreto al XOR | **SHAKE-256 a la longitud del mensaje** | Repetir la clave (XOR de clave cíclica) | Repetir clave = reutilizar keystream, el mismo fallo que reutilizar nonce. SHAKE da un keystream tan largo como el mensaje |
| Validación | Rechazar valores públicos 0, 1, p-1 y p | Aceptar cualquier valor | Evita forzar un secreto predecible (ataque de subgrupo pequeño) |

## Limitaciones conocidas (documentadas, no resueltas: fuera del alcance MSA)

1. **Sin autenticación → vulnerable a man-in-the-middle (MITM).** DH "puro" no demuestra con quién se habla. En la práctica se firma el intercambio (certificados en TLS, claves de host en SSH).
2. **XOR sin integridad.** Igual que ChaCha20 sin Poly1305: el mensaje se puede manipular sin que se detecte.
3. **El keystream depende solo del secreto.** Para varios mensajes con el mismo secreto haría falta un nonce o contador, o derivar claves con HKDF. Aquí cada ejecución genera un secreto nuevo.

## En el mundo real

TLS 1.3 y SSH usan **ECDHE (X25519)**, DH sobre curvas elípticas: claves de 32 bytes en vez de 256, más rápido y *efímero* (clave nueva por sesión), lo que aporta **forward secrecy**. La clave resultante no se usa con XOR directo: se deriva con HKDF y alimenta un AEAD como **ChaCha20-Poly1305**. Es decir: **DH sirve para acordar la clave, ChaCha20 para usarla**. Las dos partes de esta práctica son las dos mitades de un handshake real.
