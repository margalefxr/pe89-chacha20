# WORKLOG — PE 89.1 Fundamentos ChaCha20

## Pasos

| # | Paso | Resultado |
|---|---|---|
| 1 | Leer temario del Día 01, introducción, rúbrica y actividad | 7 criterios + RA2 (Diffie-Hellman) identificados |
| 2 | Crear `.venv` e instalar `pycryptodome==3.24.1` | OK |
| 3 | `cifrar()` y comparar con la salida del "Código P1" | Hex idéntico a la referencia |
| 4 | Probar nonces de 8, 12, 16 y 24 bytes | 8/12/24 aceptados; 16 da `ValueError` |
| 5 | `descifrar()` sobre el cifrado de la Parte 2 | `Este es un mensaje secreto que quiero que descifres` |
| 6 | `descifrar_desde()` con `seek(8)` | `saje ha sufrido un error en la transmision` |
| 7 | Detectar que las Partes 1 y 2 comparten clave y nonce, y demostrarlo | P2 recuperado sin la clave |
| 8 | `diffie_hellman_xor.py` para el RA2 | Misma clave en ambos lados; cifra y descifra |
| 9 | 9 pruebas con `unittest` | 9/9 OK |

## Decisiones (por qué A y no B)

| Decisión | Elegido (A) | Descartado (B) | Motivo |
|---|---|---|---|
| Librería | PyCryptodome | `pycrypto` / `cryptography` / implementación propia | `pycrypto` abandonada y con CVE; `cryptography` no tiene `seek()`; no se hace criptografía propia |
| Dependencias | Versión fijada en `requirements.txt` | `pip install` sin versión | Supply chain: instalación reproducible, sin versiones nuevas sin control ni typosquatting |
| Resincronización | `seek(8)` | Descifrar 8 bytes de relleno y tirarlos | Es el método previsto, se entiende qué hace y no genera keystream inútil |
| Nonce en producción | XChaCha20-Poly1305 con nonce aleatorio de 24 bytes | Nonce de 8 bytes aleatorio | Con 8 bytes hay riesgo real de repetición; con 24 no hace falta gestionar contador |
| DH: parámetros | Grupo 14 de RFC 3526 (2048 bits) | Primo pequeño de ejemplo | Un primo pequeño se rompe al momento |
| DH: aleatoriedad | `secrets` | `random` | `random` es predecible |
| DH: clave para el XOR | Keystream con SHAKE-256 | Repetir la clave | Repetir la clave es reutilizar keystream |
| Verificaciones | `if` + `SystemExit` | `assert` | `assert` se desactiva con `python -O` |
| Clave | En el código | Archivo `.env` | Es un dato público del enunciado; un `.env` que no protege nada daría falsa sensación de control |

## Dificultades

| ID | Dificultad | Solución |
|---|---|---|
| D-01 | El enunciado pone `source venv/bin/activate` pero el entorno es `.venv` | `source .venv/bin/activate` |
| D-02 | El cifrado de la Parte 2 en la web aparece con doble barra (`\\x83`) y así no descifra | Usar barra simple (`\x83`); el cifrado debe medir 51 bytes |
| D-03 | Reutilizar el objeto `cipher` de cifrar para descifrar lanza `TypeError` | Crear un `ChaCha20.new()` nuevo en cada operación |
| D-04 | El extra sin `seek` da bytes ilegibles | `seek(8)` antes de `decrypt()` |
| D-05 | La pregunta menciona un nonce de 16 bytes, que la librería rechaza | Documentado como respuesta: solo 8, 12 o 24 |
| D-06 | El RA2 está en la introducción pero no en la actividad ni la rúbrica | Implementado en versión mínima como extra |
| D-07 | En Windows, PowerShell puede bloquear `Activate.ps1` | `Set-ExecutionPolicy -Scope Process RemoteSigned` (solo esa sesión) |
| D-08 | XChaCha20: se asumía un contador de 64 bits | Comprobado en el código de PyCryptodome: 32 bits, máximo 256 GiB por mensaje |
