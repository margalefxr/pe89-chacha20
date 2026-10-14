# ADR-0002 — Tamaño del nonce

- **Estado:** Aceptado (ejercicio) / Recomendación (producción)
- **Fecha:** 2026-10-14

## Contexto

El enunciado fija un nonce de 8 bytes y pregunta por tamaños mayores. Se probaron 8, 12, 16 y 24 bytes con PyCryptodome.

## Opciones

| Opción | Estándar | Generación segura del nonce | Límite por mensaje |
|---|---|---|---|
| A. 8 bytes | ChaCha20 original (DJB) | Solo con contador; aleatorio no es seguro (50 % de colisión hacia ~2³² mensajes) | Prácticamente ilimitado |
| B. 12 bytes | RFC 8439 (TLS 1.3) | Contador; o aleatorio con un límite de ~2³² mensajes por clave (criterio NIST SP 800-38D) | 256 GiB |
| C. 16 bytes | — | No soportado (`ValueError`) | — |
| D. 24 bytes | XChaCha20 | **Aleatorio sin preocupaciones** | 256 GiB (en PyCryptodome usa internamente la variante de 12 bytes con contador de 32 bits) |

## Decisión

- **En el ejercicio:** A (8 bytes), porque lo fija el enunciado y hay que reproducir el resultado.
- **Recomendación para un sistema real:** **XChaCha20-Poly1305 con nonce aleatorio de 24 bytes**, cuando no haya un contador fiable; o **ChaCha20-Poly1305 de 12 bytes** cuando haga falta compatibilidad con TLS.

## Justificación

El tamaño del nonce **no aumenta la fuerza criptográfica** (la da la clave de 256 bits): **reduce la probabilidad de un fallo operativo** (repetir nonce). En la línea MSA, la opción D elimina toda la lógica de gestión del contador, menos código y menos puntos de fallo.

## Consecuencias

- Con 8 bytes es **obligatorio** un mecanismo que garantice que el nonce nunca se repite (contador persistente). Si se pierde el estado (reinicio, réplica de la VM), se reutiliza el nonce.
- Relación con la gestión de claves (NIST SP 800-57, ISO 27001 A.8.24): hay que rotar la clave antes de agotar el espacio de nonces.
