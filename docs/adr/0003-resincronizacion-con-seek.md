# ADR-0003 — Resincronizar el keystream con `seek()`

- **Estado:** Aceptado
- **Fecha:** 2026-10-14

## Contexto

Se reciben un cifrado al que le faltan los 8 primeros bytes. El receptor tiene que alinear su keystream con el del emisor.

## Opciones

| Opción | Pros | Contras |
|---|---|---|
| **A. `cipher.seek(8)`** | API oficial y explícita; coste constante aunque el salto sea grande | Ninguno relevante |
| B. `cipher.decrypt(b"\x00" * 8)` y descartar | Funciona en cualquier librería de flujo | Implícito (no se entiende el porqué sin comentario); genera keystream inútil |
| C. Reconstruir los 8 bytes | — | Imposible: la información perdida no se puede recuperar |

## Decisión

**A. `seek(8)`**: es lo que pide la rúbrica, y es más legible y eficiente.

## Consecuencias y nota de seguridad

- Se recupera `saje ha sufrido un error en la transmision`; los 8 primeros bytes (`Este men`) se pierden.
- Poder descifrar un mensaje dañado **sin ningún aviso** demuestra la falta de integridad de ChaCha20. En producción, con ChaCha20-Poly1305, el mensaje se rechazaría entero y la recuperación la haría el transporte (retransmisión TCP/QUIC). **La capa criptográfica no debe "arreglar" datos corruptos.**
