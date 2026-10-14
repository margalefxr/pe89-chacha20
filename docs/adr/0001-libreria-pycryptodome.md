# ADR-0001 — Usar PyCryptodome en vez de implementar ChaCha20 a mano

- **Estado:** Aceptado
- **Fecha:** 2026-10-14

## Contexto

El ejercicio pide cifrar y descifrar con ChaCha20 en Python usando una librería externa.

## Opciones

| Opción | Pros | Contras |
|---|---|---|
| **A. PyCryptodome** | Lo pide el enunciado; mantenida; soporta nonces de 8/12/24 bytes y `seek()`; documentación clara | Dependencia externa |
| B. `cryptography` (PyCA) | Muy usada, respaldada por OpenSSL | Su ChaCha20 solo admite un nonce de 16 bytes (contador + nonce juntos) y no tiene `seek()`: complica las Partes 1 y Extra |
| C. Implementación propia (ARX a mano) | Didáctica | **"Don't roll your own crypto"**: riesgo de errores sutiles y de canales laterales; no auditada |
| D. `pycrypto` | Misma API | **Abandonada desde 2013**, con CVE sin corregir |

## Decisión

**A. PyCryptodome**, fijada a la versión `3.24.1` en `requirements.txt`.

## Consecuencias

- Instalación reproducible y control de la cadena de suministro (ISO 27001 A.5.21).
- Se depende de un tercero: hay que vigilar sus avisos de seguridad (`pip-audit`) y actualizar la versión de forma controlada, no automática.
