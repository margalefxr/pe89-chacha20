"""
PE 89.1 - Fundamentos ChaCha20
Autor: Xavier Margalef Riestra

Cifrado y descifrado con ChaCha20 (PyCryptodome).

  - cifrar()           -> Parte 1
  - descifrar()        -> Parte 2
  - descifrar_desde()  -> Extra (resincronizar keystream con seek)
  - demo final         -> riesgo de reutilizar clave y nonce (criterio 4)

La clave y el nonce estan en el codigo porque los fija el enunciado (datos
publicos del ejercicio). En un caso real irian en un gestor de secretos.
"""

from Crypto.Cipher import ChaCha20

# Parametros del enunciado
CLAVE = b'z\xe8~"\xcayW\x14g\x18+\x1c+\xf9\x80\x06P\x9ej\x888\xb4G\xdf\xe4\xc50,\x8dY\x80\x19'
NONCE = b'\xd6\x7f6\xc7\xe8i*\xa4'

TEXTO_PLANO_P1 = "Este es un mensaje secreto que quiero cifrar"

TEXTO_CIFRADO_P2 = (
    b'Ehq0\x83\xcb\x8fo\xab\xed\xd0S\x06\xcc\xbb\xecw\xe9\xec(\x1f\xc5E\xdb'
    b'\x88\x18`W\xc3yQn\xad3\xec.\x08\x92\x8d\x8e\xbb%\x8f\x1a\xa6\xc9=\x15\x0f5\xaa'
)

# Mensaje recibido al que le faltan los 8 primeros bytes
TEXTO_CIFRADO_EXTRA = (
    b"\xad\xe2\x9a[C\xca\xa9\xadn\xf9\xaa)\x13\xc2X\x9e\x89\x19`C\xc4n\x1em"
    b"\xf8?\xe7|\x0b\xd3\xdc\x8f\xacd\x85\x0c\xb8\xc3'\x1a\x12>"
)
BYTES_PERDIDOS = 8


def _validar_parametros(clave: bytes, nonce: bytes) -> None:
    """Falla al principio con un mensaje claro si clave o nonce no son validos."""
    if len(clave) != 32:
        raise ValueError(f"La clave debe tener 32 bytes; tiene {len(clave)}")
    if len(nonce) not in (8, 12, 24):
        raise ValueError(f"El nonce debe tener 8, 12 o 24 bytes; tiene {len(nonce)}")


def cifrar(texto_plano: bytes, clave: bytes, nonce: bytes) -> bytes:
    """Parte 1: cifra con ChaCha20."""
    _validar_parametros(clave, nonce)
    cipher = ChaCha20.new(key=clave, nonce=nonce)
    return cipher.encrypt(texto_plano)


def descifrar(texto_cifrado: bytes, clave: bytes, nonce: bytes) -> bytes:
    """
    Parte 2: descifra con ChaCha20 (texto XOR mismo keystream).
    Se crea un objeto nuevo: el de cifrar tiene el contador avanzado y
    PyCryptodome no deja reutilizarlo para descifrar (TypeError).
    """
    _validar_parametros(clave, nonce)
    cipher = ChaCha20.new(key=clave, nonce=nonce)
    return cipher.decrypt(texto_cifrado)


def descifrar_desde(texto_cifrado: bytes, clave: bytes, nonce: bytes, posicion: int) -> bytes:
    """Extra: seek(posicion) adelanta el keystream para alinearlo con el emisor."""
    _validar_parametros(clave, nonce)
    cipher = ChaCha20.new(key=clave, nonce=nonce)
    cipher.seek(posicion)
    return cipher.decrypt(texto_cifrado)


def xor(a: bytes, b: bytes) -> bytes:
    """XOR byte a byte hasta la longitud del mas corto."""
    return bytes(x ^ y for x, y in zip(a, b))


if __name__ == "__main__":
    print("== PARTE 1 - Cifrado ==")
    c1 = cifrar(TEXTO_PLANO_P1.encode("utf-8"), CLAVE, NONCE)
    print(f"Tamano del nonce : {len(NONCE)} bytes")
    print(f"Cifrado (bytes)  : {c1}")
    print(f"Cifrado (hex)    : {c1.hex()}")
    # if y no assert: los assert se desactivan con python -O
    if descifrar(c1, CLAVE, NONCE).decode("utf-8") != TEXTO_PLANO_P1:
        raise SystemExit("ERROR: el descifrado no devuelve el texto original")

    print("\n== PARTE 2 - Descifrado ==")
    print(f"Texto plano      : {descifrar(TEXTO_CIFRADO_P2, CLAVE, NONCE).decode('utf-8')}")

    print("\n== EXTRA - Sincronizacion del keystream ==")
    print(f"Sin seek         : {descifrar(TEXTO_CIFRADO_EXTRA, CLAVE, NONCE)}")
    plano = descifrar_desde(TEXTO_CIFRADO_EXTRA, CLAVE, NONCE, BYTES_PERDIDOS)
    print(f"Con seek({BYTES_PERDIDOS})      : {plano.decode('utf-8')}")

    print("\n== DEMO - Reutilizacion de clave y nonce (Partes 1 y 2) ==")
    # Mismo keystream K: C1 xor C2 = P1 xor P2 -> conociendo P1 se obtiene P2 sin la clave
    p2 = xor(xor(c1, TEXTO_CIFRADO_P2), TEXTO_PLANO_P1.encode("utf-8"))
    print(f"P2 sin la clave  : {p2.decode('utf-8', errors='replace')}")
