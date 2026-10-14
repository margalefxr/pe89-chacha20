# WORKLOG — PE 89.1 Fundamentos ChaCha20

Bitácora de trabajo: qué se hizo, en qué orden y qué problemas aparecieron.

## Registro de pasos

| # | Paso | Resultado |
|---|---|---|
| 1 | Lectura del temario del Día 01 (codificación/esteganografía, ChaCha20), introducción y rúbrica | Requisitos identificados: 6 criterios + extra con `seek()` y 8 bytes perdidos |
| 2 | Creación de `.venv` e instalación de `pycryptodome==3.24.1` | OK |
| 3 | Implementación de `cifrar()` y comparación con la salida del "Código P1" | Hex idéntico al de referencia |
| 4 | Pruebas de tamaños de nonce (8, 12, 16, 24) | 8/12/24 aceptados; 16 da `ValueError` |
| 5 | Implementación de `descifrar()` y descifrado de la Parte 2 | `Este es un mensaje secreto que quiero que descifres` |
| 6 | Implementación de `descifrar_desde()` con `seek(8)` | `saje ha sufrido un error en la transmision` |
| 7 | Hallazgo: Parte 1 y Parte 2 comparten clave y nonce → demo del ataque | Se recupera P2 sin la clave |
| 8 | Tests con `unittest` (7 casos) | 7/7 OK |
| 9 | Documentación: README, ADR y evidencias | Hecho |
| 10 | Revisión de la introducción: el RA2 pide Diffie-Hellman + XOR, que no está en la Actividad | Se añade `diffie_hellman_xor.py` (librería estándar) |
| 11 | Comprobación del primo de RFC 3526: 2048 bits, primo y primo seguro ((p-1)/2 también primo) | OK |
| 12 | Tests de DH (4 casos) y segunda revisión contra la rúbrica | 11/11 OK; añadida la función del nonce y la tabla de configuración segura vs insegura |
| 13 | Revisión final: cada pregunta de la Actividad, cada criterio de la rúbrica y cada objetivo de la Introducción; verificación de afirmaciones en el código fuente de la librería; instalación limpia desde cero siguiendo el README | Corregido el contador de XChaCha20; añadidos requisito de Python ≥ 3.10, notas de Windows y versiones en la evidencia |

## Dificultades encontradas y solución

| ID | Dificultad | Causa | Solución |
|---|---|---|---|
| D-01 | El comando de activación del enunciado falla en Linux/macOS | El enunciado pone `source venv/bin/activate` pero el entorno se llama `.venv` | Usar `source .venv/bin/activate` |
| D-02 | Al copiar el cifrado de la Parte 2 desde la web aparece `\\x83` (doble barra) | La plataforma muestra el literal escapado; con doble barra Python lo interpreta como los caracteres `\`, `x`, `8`, `3` y no como el byte 0x83 | Usar una sola barra (`\x83`). Comprobación: el texto cifrado debe medir 51 bytes |
| D-03 | Reutilizar el mismo objeto `cipher` para cifrar y luego descifrar lanza `TypeError: Cipher object can only be used for encryption` | PyCryptodome bloquea mezclar operaciones en un objeto, porque el objeto guarda el contador (tras cifrar 44 bytes, el keystream sigue en el byte 44) | Crear siempre un `ChaCha20.new()` nuevo para cada operación independiente |
| D-04 | El mensaje del extra descifrado "sin más" da bytes ilegibles y `UnicodeDecodeError` | Keystream desalineado 8 bytes | `seek(8)` antes de `decrypt()` |
| D-05 | El nonce de 16 bytes que menciona la pregunta da error | PyCryptodome solo acepta 8, 12 o 24 | Documentado como respuesta (ADR-0002) |
| D-06 | Riesgo de instalar `pycrypto` por error (nombre similar) | Paquete abandonado y con CVE; mismo *namespace* `Crypto` | Fijar `pycryptodome` en `requirements.txt` |
| D-07 | El RA2 (Diffie-Hellman + XOR) aparece en la Introducción pero no en la Actividad ni en la rúbrica | Probable arrastre de otra práctica | Se implementa igualmente en versión mínima para cubrir el resultado de aprendizaje (ADR-0004) |
| D-08 | El secreto DH es un número de 2048 bits y el mensaje tiene 44 bytes: ¿cómo se hace la XOR? | Tamaños distintos | Derivar un keystream de la longitud exacta con SHAKE-256; repetir la clave se descarta por ser reutilización de keystream |
| D-09 | Un primo de ejemplo pequeño (p = 23) "funciona" pero es inseguro | Logaritmo discreto trivial | Usar el grupo 14 estandarizado de RFC 3526 |
| D-10 | En Windows, PowerShell puede bloquear `Activate.ps1` ("la ejecución de scripts está deshabilitada") | Política de ejecución por defecto de Windows | `Set-ExecutionPolicy -Scope Process RemoteSigned`, solo para esa sesión, sin cambiar la política del sistema |
| D-11 | Al documentar XChaCha20 se asumió un contador de 64 bits | Hay implementaciones distintas (libsodium usa 64 bits) | Se comprobó en el código fuente de PyCryptodome: usa la variante de 12 bytes con contador de 32 bits (256 GiB por mensaje) |

## Lecciones aprendidas

- En cifrado de flujo **el nonce es tan crítico como la clave**: no es secreto, pero **nunca** debe repetirse con la misma clave.
- **Cifrar ≠ proteger la integridad.** ChaCha20 sin Poly1305 no detecta manipulaciones ni errores de transmisión.
- Que el enunciado reutilice clave y nonce entre dos partes es un buen ejemplo de cómo un fallo de **gestión** (no del algoritmo) rompe la confidencialidad.
- **Diffie-Hellman resuelve el reparto de la clave, no la autenticación.** Sin firmar el intercambio, un atacante en medio puede suplantar a las dos partes.
